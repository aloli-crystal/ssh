require "./spec_helper"

describe SSH do
  it "expose une version" do
    SSH::VERSION.should eq("0.1.0")
  end
end
