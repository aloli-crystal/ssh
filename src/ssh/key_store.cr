module SSH
  # Découvre les clés SSH dans un dossier (par défaut `~/.ssh`) selon
  # la **convention Aloli** :
  #
  #   - clé privée : `<name>.key` (ex: `philippe.aloli.fr.key`)
  #   - clé publique : `<name>.pub` (ex: `philippe.aloli.fr.pub`)
  #
  # Le garde-fou anti-publication accidentelle tient à l'extension :
  # un `.key` ne finira jamais par mégarde dans un commit (convention
  # tipique `*.pem` ou absence d'extension qui complique les
  # `.gitignore`).
  #
  # Résolution par nom : le caller passe un nom logique (ex:
  # `philippe-aloli-fr`, forme utilisée dans les labels côté fournisseurs
  # OVH/Scaleway/Hetzner) ; le `KeyStore` applique la transformation
  # `-` → `.` et teste l'existence du fichier `<dir>/<transformé>.key`.
  #
  # Exemple :
  #
  #     store = SSH::KeyStore.new
  #     store.path_for("philippe-aloli-fr")   # => "~/.ssh/philippe.aloli.fr.key"
  #     store.path_for("inexistante")         # => nil
  class KeyStore
    DEFAULT_DIR = File.expand_path("~/.ssh", home: true)

    getter dir : String

    def initialize(@dir : String = DEFAULT_DIR)
    end

    # Retourne le chemin absolu d'une clé privée par nom logique, ou
    # nil si aucun fichier ne correspond.
    #
    # Le nom est d'abord testé tel quel, puis avec `-` remplacés par
    # `.` (convention fournisseurs ↔ convention fichiers Aloli).
    def path_for(name : String) : String?
      candidates(name).each do |candidate|
        path = File.join(@dir, "#{candidate}.key")
        return path if File.exists?(path)
      end
      nil
    end

    # Variante levée : même logique mais exception si rien trouvé.
    # Utilisée par les callers qui ne veulent pas de fallback silencieux.
    def path_for!(name : String) : String
      path_for(name) || raise KeyNotFound.new(
        "aucune clé SSH trouvée pour « #{name} » dans #{@dir} " \
        "(testé : #{candidates(name).map { |c| "#{c}.key" }.join(", ")})"
      )
    end

    # Liste des noms de clés privées disponibles dans le dossier,
    # basée sur l'existence des fichiers `*.key`. Triée.
    def available_keys : Array(String)
      return [] of String unless Dir.exists?(@dir)
      Dir.children(@dir)
        .select(&.ends_with?(".key"))
        .map { |f| f[0...-4] }
        .sort
    end

    # Candidats de nom de fichier à tester (ordre décroissant de
    # spécificité). `philippe-aloli-fr` → ["philippe-aloli-fr",
    # "philippe.aloli.fr"]. `philippe.aloli.fr` → ["philippe.aloli.fr"].
    private def candidates(name : String) : Array(String)
      result = [name]
      dotted = name.gsub('-', '.')
      result << dotted if dotted != name
      result
    end
  end

  class KeyNotFound < Exception
  end
end
