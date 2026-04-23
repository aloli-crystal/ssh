require "./ssh/version"
require "./ssh/result"
require "./ssh/key_store"
require "./ssh/connection"

# Wrapper Crystal isolé autour du binaire `ssh` système.
#
# Ce shard est prévu pour les outils de provisioning et d'automatisation
# qui doivent **ignorer complètement** la configuration utilisateur
# (`~/.ssh/config`, `~/.ssh/known_hosts`, `ssh-agent`). Chaque
# connexion utilise une clé explicitement résolue, avec
# `BatchMode=yes` (jamais de prompt) et `StrictHostKeyChecking=no`
# (hosts jetables de type rescue/bootstrap).
#
# Usage typique :
#
#     require "ssh"
#
#     store = SSH::KeyStore.new
#     key = store.path_for!("philippe-aloli-fr")
#
#     conn = SSH::Connection.new(
#       host: "ns3156789.ip-51-83-6.eu",
#       user: "root",
#       identity_file: key,
#     )
#     result = conn.exec("uname -a")
#     puts result.stdout
#
# Voir `SSH::Connection` pour la liste des options ssh forcées (et
# pourquoi), et `SSH::KeyStore` pour la convention de découverte des
# clés dans `~/.ssh/*.key`.
module SSH
end
