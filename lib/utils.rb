module Utils
  module ModuleLoaded
    def self.synchrony?
      defined?(EM::Synchrony) && EM.reactor_running?
    end

    def self.fiberpool?
      CfConsole::Application.config.middleware.middlewares.include?(Rack::FiberPool)
    end
  end

  module EMDeferredBlock
    def self.defer_block(&blk)
      f = Fiber.current

      locale = I18n.locale
      defer_proc = Proc.new do
        begin
          I18n.locale = locale
          result = blk.call
          [:success, result]
        rescue => ex
          [:error, ex]
        end
      end

      callback_proc = Proc.new { |result| f.resume(result) }

      EM.defer(defer_proc, callback_proc)

      status, result = Fiber.yield
      if status == :success
        result
      else
        raise result
      end
    end
  end

  module FiberedIterator
    def self.each(list, concurrency = 1, &blk)
      raise I18n.t('utils.argument_not_array') unless list.respond_to?(:to_a)
      error = nil
      locale = I18n.locale
      foreach = Proc.new do |obj|
        begin
          I18n.locale = locale
          blk.call(obj)
        rescue => ex
          error = ex
        end
      end
      if Utils::ModuleLoaded.synchrony? && Utils::ModuleLoaded.fiberpool?
        begin
          result = EM::Synchrony::FiberIterator.new(list, concurrency).each(foreach)
        rescue => ex
          error = I18n.t('utils.fiberiterator_exception', :msg => ex.message)
        end
      else
        result = list.each { |obj| blk.call(obj) }
      end
      raise error if !error.nil?
      result
    end

    def self.map(list, concurrency = 1, &blk)
      raise I18n.t('utils.argument_not_array') unless list.respond_to?(:to_a)
      error = nil
      locale = I18n.locale
      foreach = Proc.new do |obj, iter|
        Fiber.new {
          begin
            I18n.locale = locale
            res = blk.call(obj)
            iter.return(res)
          rescue => ex
            error = ex
            iter.return(nil)
          end
        }.resume
      end
      if Utils::ModuleLoaded.synchrony? && Utils::ModuleLoaded.fiberpool?
        begin
          result = EM::Synchrony::Iterator.new(list, concurrency).map(&foreach)
        rescue => ex
          error = I18n.t('utils.iterator_exception', :msg => ex.message)
        end
      else
        result = list.map { |obj| blk.call(obj) }
      end
      raise error if !error.nil?
      result
    end
  end

  module GitUtil
    def self.git_binary()
      git_binary = ENV['PATH'].split(':').map { |p| File.join(p, 'git') }.find { |p| File.exist?(p) } || nil
    end

    def self.git_clone(gitrepo, gitbranch, repodir)
      raise I18n.t('utils.gitrepo_blank') if gitrepo.blank?
      raise I18n.t('utils.gitbranch_blank') if gitbranch.blank?
      raise I18n.t('utils.repodir_blank') if repodir.blank?
      FileUtils.rm_rf(repodir, :secure => true)
      git_binary = git_binary()
      raise I18n.t('utils.git_not_found') if git_binary.nil?
      cmd = "#{git_binary} --git-dir=#{repodir} clone --quiet --branch=#{gitbranch} #{gitrepo} #{repodir}"
      if EM.reactor_running?
        f = Fiber.current
        EM.system(cmd) do |output, status|
          f.resume({:status => status, :output => output})
        end
        git_clone_result = Fiber.yield
        raise I18n.t('utils.git_clone_error', :msg => git_clone_result[:status].exitstatus.to_s) if git_clone_result[:status].exitstatus != 0
      else
        stdout = `#{cmd} 2>&1`
        raise I18n.t('utils.git_clone_error', :msg => $?.exitstatus.to_s) if $?.to_i != 0
      end
    end

    def self.git_uri_valid?(uri)
      Addressable::URI.parse(uri)
      uri_regex = Regexp.new("^git://[a-z0-9]+([-.]{1}[a-z0-9]+)*.[a-z]{2,5}(([0-9]{1,5})?/.*)?.git$", Regexp::IGNORECASE)
      return true if uri =~ uri_regex
      false
    rescue Addressable::URI::InvalidURIError
      false
    end
  end

  module ZipUtil
    require 'zip/zip'
    def self.pack_files(zipfile, files)
      raise I18n.t('utils.zipfile_blank') if zipfile.blank?
      raise I18n.t('utils.argument_not_array') unless files.respond_to?(:to_a)
      raise I18n.t('utils.files_empty') if files.empty?
      pack_proc = Proc.new {
        FileUtils.rm_f(zipfile)
        Zip::ZipFile::open(zipfile, true) do |zf|
          files.each do |f|
            zf.add(f[:zn], f[:fn])
          end
        end
      }
      if EM.reactor_running?
        EMDeferredBlock::defer_block(&pack_proc)
      else
        pack_proc.call
      end
    end
  end
  
  module CFCTAR
    require 'zlib'
    require 'fileutils'
    require 'rubygems/package'
    
      def self.ungzip(tarfile)
        z = Zlib::GzipReader.open(tarfile)
        unzipped = StringIO.new(z.read)
        z.close
        unzipped
      end

      def self.untar(io, destination)
        Gem::Package::TarReader.new io do |tar|
          tar.each do |tarfile|
            destination_file = File.join destination, tarfile.full_name
            if tarfile.directory?
              FileUtils.mkdir_p destination_file
            else
                destination_directory = File.dirname(destination_file)
                FileUtils.mkdir_p destination_directory unless File.directory?(destination_directory)
                File.open destination_file, "wb" do |f|
                  f.print tarfile.read
                end
             end
          end
       end
      end
       
       def self.extract(tarfile, exploded_dir)    
         extract_proc = Proc.new {
         unzippedtar = ungzip(tarfile)
         untar(unzippedtar, exploded_dir)
         }
          if EM.reactor_running?
            EMDeferredBlock::defer_block(&extract_proc)
          else
            extract_proc.call
          end
       end
    
  end

  module FileUtilsAsync
    
    def self.rm_rf(dest_dir)
      rm_rf_async = Proc.new {    
      FileUtils.rm_rf(dest_dir)
      }
      if EM.reactor_running?
        EMDeferredBlock::defer_block(&rm_rf_async)
      else
          rm_fr_async.call  
      end    
    end
    
    def self.rm_f(dest_dir)
      rm_f_async = Proc.new {    
      FileUtils.rm_f(dest_dir)
      }
      if EM.reactor_running?
        EMDeferredBlock::defer_block(&rm_f_async)
      else
          rm_f_async.call  
      end    
    end
    
    def self.cp_r(source, target)
      cp_r_async = Proc.new {
        FileUtils.cp_r(source, target)
      }
      if EM.reactor_running?
        EMDeferredBlock::defer_block(&cp_r_async)
      else
          cp_r_async.call  
      end 
    end
    
    def self.cp(source, target)
      cp_async = Proc.new {
        FileUtils.cp(source, target)
      }
      if EM.reactor_running?
        EMDeferredBlock::defer_block(&cp_async)
      else
          cp_async.call  
      end 
    end
    
    def self.mkdir(dir)
      mkdir_async = Proc.new {
        FileUtils.mkdir(dir)
      }
      if EM.reactor_running?
        EMDeferredBlock::defer_block(&mkdir_async)
      else
          mkdir_async.call  
      end 
    end   
    
    def self.new(filename, mode)
      new_async = Proc.new {
        File.new(filename, mode)
      }
      if EM.reactor_running?
        EMDeferredBlock::defer_block(&new_async)
      else
        new_async.call  
      end 
    end 
    
  end  
  
  module DirAsync
    
    def self.glob(pattern, filename)
      dir_glob = Proc.new {
      Dir.glob(pattern, filename)
      }
      if EM.reactor_running?
        EMDeferredBlock::defer_block(&dir_glob)
      else
        dir_glob.call  
      end 
    end
    
  end
        

end