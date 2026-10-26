require "./spec_helper"
require "yaml"

describe SSH do
  it "expose une version" do
    yml = YAML.parse(File.read(File.join(__DIR__, "..", "shard.yml")))
    SSH::VERSION.should eq(yml["version"].as_s)
  end
end
