require "./spec_helper"

describe SSH::Connection do
  it "valeurs par défaut : user=root, port=22, pas d'identity_file" do
    c = SSH::Connection.new(host: "example.com")
    c.host.should eq("example.com")
    c.user.should eq("root")
    c.port.should eq(22)
    c.identity_file.should be_nil
  end

  describe "#ssh_args" do
    it "inclut -F /dev/null pour ignorer ~/.ssh/config" do
      c = SSH::Connection.new(host: "h1")
      args = c.ssh_args("uname -a")
      args.should contain("-F")
      idx = args.index("-F").not_nil!
      args[idx + 1].should eq("/dev/null")
    end

    it "force les options d'isolation (known_hosts, agent, batchmode)" do
      c = SSH::Connection.new(host: "h1")
      args = c.ssh_args("echo hi")
      joined = args.join(" ")
      joined.should contain("StrictHostKeyChecking=no")
      joined.should contain("UserKnownHostsFile=/dev/null")
      joined.should contain("GlobalKnownHostsFile=/dev/null")
      joined.should contain("BatchMode=yes")
      joined.should contain("IdentitiesOnly=yes")
      joined.should contain("IdentityAgent=none")
      # ConnectTimeout limite le handshake TCP à 10s, évite de
      # bloquer indéfiniment sur un serveur en cours de boot.
      joined.should contain("ConnectTimeout=10")
      # IPv4 forcé : évite les stalls « banner exchange » quand l'IPv6
      # d'un host est cassé/filtré (cf. bastion zsbg, 16 juin 2026).
      joined.should contain("AddressFamily=inet")
    end

    it "active ControlMaster pour multiplexer plusieurs exec vers la même cible" do
      c = SSH::Connection.new(host: "h1")
      joined = c.ssh_args("echo hi").join(" ")
      # Multiplexage natif OpenSSH : le 1er ssh ouvre un master,
      # les suivants vers la même cible se branchent dessus via
      # un socket UNIX local. Évite le ré-handshake TCP+TLS+auth
      # à chaque exec (gain ~10× sur des flows à 50+ exec).
      joined.should contain("ControlMaster=auto")
      joined.should contain("ControlPath=/tmp/ssh-%C-%i")
      joined.should contain("ControlPersist=10m")
    end

    it "le ControlPath utilise des placeholders OpenSSH safe (%C hash + %i uid)" do
      c = SSH::Connection.new(host: "very-long-hostname.example.com", port: 12345, user: "deploy")
      joined = c.ssh_args("x").join(" ")
      # %C est un hash 8 chars (host+port+user+localhost). %i est
      # l'uid local. Cela garantit l'unicité par cible et reste
      # bien sous la limite UNIX socket de 104 chars (macOS).
      # Le path littéral DOIT être présent comme template — c'est
      # OpenSSH qui expanse à l'exécution.
      joined.should contain("ControlPath=/tmp/ssh-%C-%i")
      # Sanity check : pas de %h ni de %p dans le path (on ne
      # veut pas que des hostnames longs explosent la limite
      # de socket UNIX).
      joined.should_not contain("ControlPath=/tmp/ssh-%h")
    end

    it "N'impose PAS ServerAliveInterval (éviterait de couper les " \
       "commandes longues légitimes comme `dd` ou `pkg install`)" do
      c = SSH::Connection.new(host: "h1")
      c.ssh_args("x").join(" ").should_not contain("ServerAlive")
    end

    it "ajoute -i <path> quand identity_file est fourni" do
      c = SSH::Connection.new(host: "h1", identity_file: "/tmp/k.key")
      args = c.ssh_args("date")
      args.should contain("-i")
      idx = args.index("-i").not_nil!
      args[idx + 1].should eq("/tmp/k.key")
    end

    it "pas de -i quand identity_file = nil" do
      c = SSH::Connection.new(host: "h1")
      c.ssh_args("date").should_not contain("-i")
    end

    it "utilise le port passé" do
      c = SSH::Connection.new(host: "h1", port: 2222)
      args = c.ssh_args("x")
      args.should contain("-p")
      idx = args.index("-p").not_nil!
      args[idx + 1].should eq("2222")
    end

    it "termine par user@host puis commande" do
      c = SSH::Connection.new(host: "serv", user: "deploy")
      args = c.ssh_args("ls -la")
      args[-2].should eq("deploy@serv")
      args[-1].should eq("ls -la")
    end

    it "les options FORCED ne peuvent pas être écrasées par l'appelant" do
      c = SSH::Connection.new(
        host: "h1",
        options: {"StrictHostKeyChecking" => "yes", "Custom" => "value"},
      )
      joined = c.ssh_args("x").join(" ")
      joined.should contain("StrictHostKeyChecking=no")
      joined.should_not contain("StrictHostKeyChecking=yes")
      joined.should contain("Custom=value")
    end

    describe "ProxyJump (saut bastion)" do
      it "convertit ProxyJump en ProxyCommand qui transporte la clé -i" do
        c = SSH::Connection.new(
          host: "192.168.42.32", user: "admin",
          identity_file: "/keys/pne.key",
          options: {"ProxyJump" => "admin@zsbg.example.net"},
        )
        joined = c.ssh_args("uname -s").join(" ")
        # plus de ProxyJump nu (qui perdrait la clé au saut)…
        joined.should_not contain("ProxyJump=")
        # …mais un ProxyCommand qui réémet la MÊME clé + les options hermétiques
        joined.should contain("ProxyCommand=ssh -F /dev/null -i /keys/pne.key")
        joined.should contain("-W %h:%p admin@zsbg.example.net")
        joined.should contain("IdentitiesOnly=yes")
      end

      it "ne réémet pas le multiplexage Control* dans le saut" do
        c = SSH::Connection.new(
          host: "h", identity_file: "/k",
          options: {"ProxyJump" => "u@b"},
        )
        pc = c.ssh_args("x").join(" ")
        # le ProxyCommand (forward stdio one-shot) n'a pas besoin de ControlMaster
        pc.scan(/ControlMaster/).size.should eq(1) # seulement la connexion finale
      end

      it "gère un bastion avec port (host:port → -p)" do
        c = SSH::Connection.new(
          host: "h", identity_file: "/k",
          options: {"ProxyJump" => "u@b.example.net:2222"},
        )
        joined = c.ssh_args("x").join(" ")
        joined.should contain("-p 2222")
        joined.should contain("-W %h:%p u@b.example.net") # host sans le :port
      end

      it "sans repli : ProxyCommand inchangé (pas de sh -c)" do
        c = SSH::Connection.new(host: "h", identity_file: "/k", options: {"ProxyJump" => "u@a"})
        c.ssh_args("x").join(" ").should_not contain("sh -c")
      end

      it "replis : essaie chaque rebond dans l'ordre et annonce le repli" do
        c = SSH::Connection.new(
          host: "192.168.42.11", identity_file: "/k",
          options: {"ProxyJump" => "u@a.example.net"},
          jump_fallbacks: ["u@b.example.net", "u@c.example.net", "u@a.example.net"],
        )
        pc = c.ssh_args("x").find!(&.starts_with?("ProxyCommand=")).lchop("ProxyCommand=")
        pc.should start_with("sh -c '")
        pc.index!("-W %h:%p u@a.example.net").should be < pc.index!("-W %h:%p u@b.example.net")
        pc.index!("-W %h:%p u@b.example.net").should be < pc.index!("-W %h:%p u@c.example.net")
        pc.scan("-W %h:%p u@a.example.net").size.should eq(1) # doublon retiré
        pc.should contain("rebond u@a.example.net injoignable, essai par u@b.example.net")
        pc.scan("-i /k").size.should eq(3) # la clé à chaque rebond
      end

      it "replis : commande valide pour sh, chaîne qui s'arrête au premier rebond qui marche" do
        dir = File.tempname("ssh-fallback")
        Dir.mkdir(dir)
        # faux `ssh` : échoue pour le rebond `dead`, réussit sinon, et note qui a servi
        File.write(File.join(dir, "ssh"), "#!/bin/sh\nfor a; do last=$a; done\necho $last >> #{dir}/log\ncase $last in *dead*) exit 255;; esac\n")
        File.chmod(File.join(dir, "ssh"), 0o755)
        c = SSH::Connection.new(host: "t", options: {"ProxyJump" => "u@dead"}, jump_fallbacks: ["u@ok", "u@spare"])
        pc = c.ssh_args("x").find!(&.starts_with?("ProxyCommand=")).lchop("ProxyCommand=").gsub("%h:%p", "t:22")
        err = IO::Memory.new
        st = Process.run("sh", ["-c", pc], env: {"PATH" => "#{dir}:/usr/bin:/bin"}, error: err)
        st.success?.should be_true
        File.read_lines(File.join(dir, "log")).should eq ["u@dead", "u@ok"]
        err.to_s.should contain("rebond u@dead injoignable, essai par u@ok")
      ensure
        FileUtils.rm_rf(dir) if dir
      end
    end
  end

  describe "#scp_args" do
    it "utilise -P majuscule (spécificité scp) et -F /dev/null" do
      c = SSH::Connection.new(host: "h1", port: 2222)
      args = c.scp_args("/local", "/remote")
      args.should contain("-F")
      args.should contain("-P")
      idx = args.index("-P").not_nil!
      args[idx + 1].should eq("2222")
    end

    it "termine par source puis destination" do
      c = SSH::Connection.new(host: "h1")
      args = c.scp_args("a.txt", "deploy@h1:/b.txt")
      args[-2].should eq("a.txt")
      args[-1].should eq("deploy@h1:/b.txt")
    end

    it "inclut les options d'isolation comme ssh" do
      c = SSH::Connection.new(host: "h1")
      joined = c.scp_args("a", "b").join(" ")
      joined.should contain("UserKnownHostsFile=/dev/null")
      joined.should contain("BatchMode=yes")
    end
  end
end
