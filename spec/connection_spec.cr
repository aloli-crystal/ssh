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
