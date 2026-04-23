require "./spec_helper"
require "file_utils"

describe SSH::KeyStore do
  it "résout une clé par nom exact" do
    tmp = File.tempname("ssh-keystore-exact")
    Dir.mkdir_p(tmp)
    File.write(File.join(tmp, "philippe.aloli.fr.key"), "fake")
    store = SSH::KeyStore.new(dir: tmp)
    store.path_for("philippe.aloli.fr").should eq(File.join(tmp, "philippe.aloli.fr.key"))
  ensure
    FileUtils.rm_rf(tmp.not_nil!) if tmp && Dir.exists?(tmp)
  end

  it "convertit `-` en `.` (convention Aloli)" do
    tmp = File.tempname("ssh-keystore-conv")
    Dir.mkdir_p(tmp)
    File.write(File.join(tmp, "philippe.aloli.fr.key"), "fake")
    store = SSH::KeyStore.new(dir: tmp)
    store.path_for("philippe-aloli-fr").should eq(File.join(tmp, "philippe.aloli.fr.key"))
  ensure
    FileUtils.rm_rf(tmp.not_nil!) if tmp && Dir.exists?(tmp)
  end

  it "retourne nil quand aucune clé ne correspond" do
    tmp = File.tempname("ssh-keystore-none")
    Dir.mkdir_p(tmp)
    store = SSH::KeyStore.new(dir: tmp)
    store.path_for("inconnue").should be_nil
  ensure
    FileUtils.rm_rf(tmp.not_nil!) if tmp && Dir.exists?(tmp)
  end

  it "path_for! lève avec un message explicite si rien trouvé" do
    tmp = File.tempname("ssh-keystore-bang")
    Dir.mkdir_p(tmp)
    store = SSH::KeyStore.new(dir: tmp)
    expect_raises(SSH::KeyNotFound, /aucune clé SSH trouvée pour « mystere »/) do
      store.path_for!("mystere")
    end
  ensure
    FileUtils.rm_rf(tmp.not_nil!) if tmp && Dir.exists?(tmp)
  end

  it "liste les clés disponibles triées" do
    tmp = File.tempname("ssh-keystore-list")
    Dir.mkdir_p(tmp)
    File.write(File.join(tmp, "zeta.key"), "fake")
    File.write(File.join(tmp, "alpha.aloli.fr.key"), "fake")
    File.write(File.join(tmp, "readme.txt"), "not a key")
    File.write(File.join(tmp, "alpha.aloli.fr.pub"), "not a key")
    store = SSH::KeyStore.new(dir: tmp)
    store.available_keys.should eq(["alpha.aloli.fr", "zeta"])
  ensure
    FileUtils.rm_rf(tmp.not_nil!) if tmp && Dir.exists?(tmp)
  end

  it "available_keys retourne tableau vide si le dossier n'existe pas" do
    store = SSH::KeyStore.new(dir: "/chemin/totalement/inexistant/pour/test")
    store.available_keys.should eq([] of String)
  end
end
