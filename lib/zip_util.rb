require 'zip/zipfilesystem'

module CFCZIP
  
  require 'utils'

  class ZipUtil
    PACK_EXCLUSION_GLOBS = ['..', '.', '*~', '#*#', '*.log']
    class << self
      def entry_lines(file)
        contents = nil
        unless contents
          entries = []
          extract_proc = Proc.new {
          Zip::ZipFile.foreach(file) { |zentry| entries << zentry }
           }
          if EM.reactor_running?
            Utils::EMDeferredBlock::defer_block(&extract_proc)
          else
            extract_proc.call
          end
          contents = entries.join("\n")
        end
        contents
      end

      def unpack(file, dest)
        extract_proc = Proc.new {
        Zip::ZipFile.foreach(file) do |zentry|
          epath = "#{dest}/#{zentry}"
          dirname = File.dirname(epath)
          FileUtils.mkdir_p(dirname) unless File.exists?(dirname)
          zentry.extract(epath) unless File.exists?(epath)
        end
                 }
          if EM.reactor_running?
            Utils::EMDeferredBlock::defer_block(&extract_proc)
          else
            extract_proc.call
          end
      end

      def get_files_to_pack(dir)
        Dir.glob("#{dir}/**/*", File::FNM_DOTMATCH).select do |f|
          process = true
          PACK_EXCLUSION_GLOBS.each { |e| process = false if File.fnmatch(e, File.basename(f)) }
          process && File.exists?(f)
        end
      end

      def pack(dir, zipfile)
        extract_proc = Proc.new {
        Zip::ZipFile::open(zipfile, true) do |zf|
          get_files_to_pack(dir).each do |f|
            zf.add(f.sub("#{dir}/",''), f)
          end
        end
                 }
          if EM.reactor_running?
            Utils::EMDeferredBlock::defer_block(&extract_proc)
          else
            extract_proc.call
          end
      end
      
    end
  end
end