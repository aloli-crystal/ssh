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
