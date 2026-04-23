module SSH
  # Résultat d'une exécution distante. Les champs `stdout`/`stderr` sont
  # capturés et retournés tels quels, sans découpage ligne.
  struct Result
    getter stdout : String
    getter stderr : String
    getter exit_code : Int32

    def initialize(@stdout : String, @stderr : String, @exit_code : Int32)
    end

    def success? : Bool
      @exit_code == 0
    end
  end

  # Levée quand une commande distante retourne un code non nul et que
  # `raise_on_error` vaut true (défaut).
  class CommandFailed < Exception
    getter command : String
    getter result : Result

    def initialize(@command : String, @result : Result)
      super(build_message)
    end

    private def build_message : String
      String.build do |io|
        io << "commande distante échouée (exit " << @result.exit_code << ") : " << @command
        unless @result.stderr.empty?
          io << '\n' << "stderr: " << @result.stderr.strip
        end
      end
    end
  end
end
