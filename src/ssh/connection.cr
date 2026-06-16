require "process"

module SSH
  # Connexion SSH **isolée** vers un hôte distant.
  #
  # Contrairement à un `ssh` lancé à la main, cette connexion ignore
  # totalement l'environnement utilisateur :
  #
  #   - `~/.ssh/config` n'est **pas** lu (`-F /dev/null`)
  #   - `~/.ssh/known_hosts` n'est **pas** lu ni écrit
  #     (`UserKnownHostsFile=/dev/null`, `GlobalKnownHostsFile=/dev/null`)
  #   - `ssh-agent` est **ignoré** (`IdentityAgent=none`)
  #   - seule la clé passée en `identity_file` est essayée
  #     (`IdentitiesOnly=yes`)
  #   - aucun prompt interactif n'est possible (`BatchMode=yes` : ni
  #     mot de passe, ni keyboard-interactive, ni confirmation de clé)
  #   - les changements de clé d'hôte ne bloquent pas
  #     (`StrictHostKeyChecking=no`) — adapté aux flows
  #     rescue/bootstrap où la clé change à chaque reboot
  #
  # Conséquence pratique : deux postes avec des configurations ssh
  # différentes exécuteront le même code de la même manière. Aucune
  # pollution croisée avec les sessions interactives de l'utilisateur.
  #
  # **Sécurité** : `StrictHostKeyChecking=no` laisse théoriquement la
  # porte à un MITM entre le poste et l'hôte distant. Ce wrapper est
  # prévu pour des outils de provisioning qui parlent à des rescue ou
  # des images fraîchement installées — contextes où la clé d'hôte
  # n'est de toute façon pas stable. Si vous avez besoin de vérifier
  # une clé d'hôte stable, utilisez `ssh` directement, pas ce shard.
  class Connection
    # Options ssh forcées sur toutes les connexions. L'appelant peut
    # ajouter des options via le paramètre `options`, mais celles-ci
    # ne peuvent pas être écrasées (elles sont ajoutées *après* pour
    # gagner par ordre d'apparition côté `ssh -o`).
    FORCED_OPTIONS = {
      "StrictHostKeyChecking" => "no",
      "UserKnownHostsFile"    => "/dev/null",
      "GlobalKnownHostsFile"  => "/dev/null",
      "LogLevel"              => "ERROR",
      "BatchMode"             => "yes",
      # Force l'IPv4. Si un host a un AAAA mais que l'IPv6 est cassé/filtré
      # (très courant : pas de route IPv6 sortante, ou sshd public en v4
      # seulement derrière un pare-feu), ssh peut choisir l'IPv6 de façon
      # non déterministe et bloquer « during banner exchange ». Observé le
      # 16 juin 2026 sur un saut ProxyJump vers un bastion (zsbg) dont
      # l'IPv6 ne répondait pas. beryl adresse ses hôtes en IPv4 (noms
      # hébergeur / IP vRack privées) → IPv4 forcé évite ce stall.
      "AddressFamily"  => "inet",
      "IdentitiesOnly" => "yes",
      "IdentityAgent"  => "none",
      # ConnectTimeout limite UNIQUEMENT le temps du handshake TCP :
      # si le serveur n'accepte pas la connexion en moins de 10s,
      # ssh abandonne cet essai (l'appelant peut re-tenter). Sans
      # ça, ssh peut bloquer plusieurs minutes quand un serveur est
      # en cours de redémarrage (rescue pas encore prêt), et la
      # boucle de polling au-dessus ne sort jamais. Observé sur
      # Dedibox rescue le 24 avril 2026 : sshd démarre ~20s après
      # le boot, le 1er ssh de beryl restait bloqué.
      #
      # N'impacte PAS la durée des commandes en cours (seul le
      # handshake de connexion est concerné). Pas de ServerAliveInterval
      # forcé pour ne pas couper des commandes longues légitimes
      # (ex: `dd` ou `pkg install` pendant le bootstrap).
      "ConnectTimeout" => "10",
      #
      # ControlMaster — multiplexage des connexions SSH. Évite le
      # ré-handshake (TCP + TLS + auth, ~100-300 ms par exec selon
      # RTT) à chaque commande quand on enchaîne plusieurs exec
      # vers la même cible. Le 1er ssh ouvre la session et écrit
      # un socket UNIX local ; les ssh suivants vers la même cible
      # se branchent sur ce socket. Gain typique : 10× plus rapide
      # sur un flow comme `beryl apply` qui peut faire 50-100 exec.
      #
      # `auto` = active mode master au 1er exec, slave aux suivants.
      # `ControlPath` utilise `%C` (hash 8 chars host+port+user+localhost,
      # garantit l'unicité par cible et reste court) + `%i` (uid local,
      # cloisonne entre users sur un /tmp partagé). Le path total
      # fait ~30 chars, largement sous la limite UNIX socket de
      # 104 chars (macOS) / 108 (Linux).
      # `ControlPersist=10m` garde le master vivant 10 min après le
      # dernier exec — utile si beryl tourne en boucle (re-test,
      # re-apply rapides). Au-delà, le master se ferme tout seul ;
      # le ssh suivant rouvre une session.
      #
      # Si beryl plante, le socket reste sur disque ; au prochain
      # run, ssh détecte un master orphelin et le nettoie. Aucune
      # action de cleanup à faire côté Crystal.
      "ControlMaster"  => "auto",
      "ControlPath"    => "/tmp/ssh-%C-%i",
      "ControlPersist" => "10m",
    }

    getter host : String
    getter user : String
    getter port : Int32
    getter identity_file : String?
    getter options : Hash(String, String)

    # Crée une connexion vers `host` pour l'utilisateur `user` sur le
    # port `port`. Si `identity_file` est fourni, il est passé en `-i`
    # et aucune autre clé n'est essayée (grâce à `IdentitiesOnly=yes`).
    # Sinon aucune clé n'est fournie → l'auth publickey échouera avec
    # un message clair (cas « pas de clé résoluble »).
    def initialize(
      @host : String,
      @user : String = "root",
      @port : Int32 = 22,
      @identity_file : String? = nil,
      @options : Hash(String, String) = {} of String => String,
    )
    end

    # Exécute une commande distante. Lève `CommandFailed` si
    # `exit_code != 0`, sauf si `raise_on_error: false`.
    #
    # `stdin` : contenu à piper sur l'entrée standard distante. Quand
    # fourni, on n'ajoute pas `-n` à l'appel ssh (sinon le pipe est
    # court-circuité). Quand absent, on passe `-n` pour fermer stdin
    # à la source — indispensable sur macOS où `Process.run` peut
    # laisser le canal ssh ouvert.
    def exec(
      command : String,
      stdin : String? = nil,
      raise_on_error : Bool = true,
    ) : Result
      stdout_io = IO::Memory.new
      stderr_io = IO::Memory.new

      args = stdin ? ssh_args(command) : ["-n"] + ssh_args(command)

      status = if stdin
                 Process.run(
                   command: "ssh",
                   args: args,
                   input: IO::Memory.new(stdin),
                   output: stdout_io,
                   error: stderr_io,
                 )
               else
                 Process.run(
                   command: "ssh",
                   args: args,
                   output: stdout_io,
                   error: stderr_io,
                 )
               end

      result = Result.new(stdout_io.to_s, stderr_io.to_s, status.exit_code)
      raise CommandFailed.new(command, result) if raise_on_error && !result.success?
      result
    end

    # Écrit `content` dans `remote_path` via `cat > …`. Si `mode` est
    # fourni, chmode le fichier distant.
    def write_file(remote_path : String, content : String, mode : String? = nil) : Nil
      exec("cat > #{Process.quote(remote_path)}", stdin: content)
      exec("chmod #{mode} #{Process.quote(remote_path)}") if mode
    end

    # Transfère un fichier local vers la cible via `scp`.
    def upload(local_path : String, remote_path : String) : Nil
      status = Process.run(
        command: "scp",
        args: scp_args(local_path, "#{@user}@#{@host}:#{remote_path}"),
      )
      raise "scp échoué (exit #{status.exit_code}) : #{local_path} → #{@host}:#{remote_path}" unless status.success?
    end

    # Récupère un fichier distant via `scp`.
    def download(remote_path : String, local_path : String) : Nil
      status = Process.run(
        command: "scp",
        args: scp_args("#{@user}@#{@host}:#{remote_path}", local_path),
      )
      raise "scp échoué (exit #{status.exit_code}) : #{@host}:#{remote_path} → #{local_path}" unless status.success?
    end

    # Liste des arguments passés au binaire `ssh` pour exécuter
    # `command`. Exposée pour permettre l'inspection et les tests.
    def ssh_args(command : String) : Array(String)
      base_args + ["#{@user}@#{@host}", command]
    end

    # Liste des arguments passés au binaire `scp` pour transférer
    # `source` vers `destination`. Exposée pour les tests.
    def scp_args(source : String, destination : String) : Array(String)
      args = [] of String
      args << "-F" << "/dev/null"
      args << "-P" << @port.to_s
      if identity = @identity_file
        args << "-i" << identity
      end
      merged_options.each do |key, value|
        args << "-o" << "#{key}=#{value}"
      end
      args << source << destination
      args
    end

    private def base_args : Array(String)
      args = [] of String
      args << "-F" << "/dev/null"
      args << "-p" << @port.to_s
      if identity = @identity_file
        args << "-i" << identity
      end
      merged_options.each do |key, value|
        args << "-o" << "#{key}=#{value}"
      end
      args
    end

    # Fusion des options : FORCED gagne toujours, puis celles de
    # l'appelant. Les deux catégories sont émises (ssh prend la
    # première rencontrée), donc en plaçant FORCED en tête on garantit
    # qu'elles l'emportent.
    private def merged_options : Hash(String, String)
      result = {} of String => String
      FORCED_OPTIONS.each { |k, v| result[k] = v }
      @options.each { |k, v| result[k] = v unless FORCED_OPTIONS.has_key?(k) }
      # `ProxyJump` nu est un piège ici : le saut hérite de `-F /dev/null`
      # (config ignorée) mais PAS du `-i identity_file` → il tenterait la clé
      # par défaut (`~/.ssh/id_*`) et se ferait refuser. On le convertit en
      # `ProxyCommand` explicite qui transporte la MÊME clé + les options
      # hermétiques jusqu'au bastion.
      if jump = result.delete("ProxyJump")
        result["ProxyCommand"] = proxy_command_for(jump)
      end
      result
    end

    # Construit le `ProxyCommand` vers le bastion `jump` (`[user@]host[:port]`),
    # en réémettant `-i identity_file` + les options forcées d'auth/hermétiques
    # (pas le multiplexage `Control*`, inutile pour un forward stdio `-W`), pour
    # que le saut soit aussi authentifié et hermétique que la connexion finale.
    private def proxy_command_for(jump : String) : String
      parts = ["ssh", "-F", "/dev/null"]
      pre, sep, post = jump.rpartition(':')
      host_spec = jump
      if !sep.empty? && (p = post.to_i?)
        host_spec = pre
        parts << "-p" << p.to_s
      end
      if id = @identity_file
        parts << "-i" << id
      end
      FORCED_OPTIONS.each do |k, v|
        next if k.starts_with?("Control")
        parts << "-o" << "#{k}=#{v}"
      end
      parts << "-W" << "%h:%p" << host_spec
      parts.join(' ')
    end
  end
end
