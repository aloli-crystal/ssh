require "./spec_helper"

describe SSH::Result do
  it "success? vrai quand exit_code = 0" do
    SSH::Result.new("ok", "", 0).success?.should be_true
  end

  it "success? faux dès qu'exit_code != 0" do
    SSH::Result.new("", "err", 1).success?.should be_false
    SSH::Result.new("", "", 255).success?.should be_false
  end
end

describe SSH::CommandFailed do
  it "message inclut le code et la commande" do
    result = SSH::Result.new("", "boom", 2)
    ex = SSH::CommandFailed.new("ls /nope", result)
    msg = ex.message.not_nil!
    msg.should contain("exit 2")
    msg.should contain("ls /nope")
    msg.should contain("boom")
  end

  it "message sans section stderr quand stderr est vide" do
    result = SSH::Result.new("", "", 1)
    ex = SSH::CommandFailed.new("false", result)
    ex.message.not_nil!.should_not contain("stderr:")
  end

  it "expose la commande et le résultat" do
    result = SSH::Result.new("out", "err", 3)
    ex = SSH::CommandFailed.new("cmd", result)
    ex.command.should eq("cmd")
    ex.result.should eq(result)
  end
end
