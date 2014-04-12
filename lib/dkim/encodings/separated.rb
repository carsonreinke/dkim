module Dkim
  module Encodings
    module Separated
      {:Colon => ':', :Pipe => '|', :ForwardSlash => '/'}.each do |mod,separator|
        mod_obj = const_set(mod, Module.new())
        mod_obj.module_eval(%(
          SEPARATOR = "#{separator}".freeze()
        
          def encode(v)
            super(v.join(SEPARATOR))
          end
      
          def decode(v)
            v = super(v).to_s()
            v.gsub!(/\\s+\#{SEPARATOR}/, SEPARATOR)
            v.gsub!(/\#{SEPARATOR}\\s+/, SEPARATOR)
            v.split(SEPARATOR)
          end
        ))
      end
    end
  end
end
