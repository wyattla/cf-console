class AppsController < ApplicationController
  def index
    begin
      app = App.new(@cf_client)
      @apps = Utils::FiberedIterator.map(app.find_all_apps(), configatron.reactor_iterator.concurrency) do |app_info|
        app.find(app_info[:name])
      end
      @available_instances = find_available_instances('STOPPED', 1, 0)
      available_memsizes = find_available_memsizes('STOPPED', 0, 1)
      @available_memsizes = []
      available_memsizes.each do |key, value|
        @available_memsizes << [value, key]
      end
      @available_frameworks = find_available_frameworks_runtimes()
      @available_services = find_available_services()
      if configatron.suggest.app.url
        host = @cf_target_url.split("//")[1]
        @newapp_default_urldomain = host.split(".").drop(1).join(".")
      end
      @instances = 1
    rescue Exception => ex
      flash[:alert] = ex.message
    end
  end

  def create
    @name = params[:name]
    @instances = params[:instances]
    @memsize = params[:memsize]
    @type = params[:type]
    @url = params[:url]
    @service = params[:service]
    @deployform = params[:deployform]
    @gitrepo = params[:gitrepo]
    @gitbranch = params[:gitbranch]
    localdeploy = params[:file]['file']
    httplocation = params[:httplocation]
    app_created = false
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    elsif @instances.blank?
      flash[:alert] = I18n.t('apps.controller.instances_blank')
    elsif @memsize.blank?
      flash[:alert] = I18n.t('apps.controller.memsize_blank')
    elsif @type.blank?
      flash[:alert] = I18n.t('apps.controller.type_blank')
    elsif @url.blank?
      flash[:alert] = I18n.t('apps.controller.url_blank')
    else
      begin
        @name = @name.strip.downcase
        framework, runtime = @type.split("/")
        file_path = nil
        filetype = nil
        unless !localdeploy
          unless request.get?
            if file_path = uploadfile(localdeploy)
               #detect_framework(file_path, framework)
            end
          end
        end 
        unless !httplocation
          unless request.get?
            file_path, filetype = downloadfile(@httplocation)   
          end
        end
        @url = @url.strip.gsub(/^http(s*):\/\//i, '').downcase
        app = App.new(@cf_client)
        manifestarray = app.create(@name, @instances, @memsize, @url, framework, runtime, @service)
         #upload application file to cloudfoundry and create app in there
        upload_app_bits2cf(@name, file_path, manifestarray) 
        logger.info "checking app created"
        #@new_app = [] << app.find(@name)
        flash[:notice] = I18n.t('apps.controller.app_created', :name => @name)
        app_created = true
      rescue Exception => ex
        flash[:alert] = ex.message
      ensure
        # Cleanup if we created file and directory.
        logger.info "starting cleanup"
        if file_path
          if file_path.to_s =~ /\.zip$/
            dir = File.dirname(file_path.to_s)
            filename = File.basename(file_path.to_s, ".zip")
            dest_dir = dir + "/" + filename
            Utils::FileUtilsAsync.rm_rf(dest_dir)
            logger.info "Cleaned up"
          end
          Utils::FileUtilsAsync.rm_f(file_path)
          logger.info "Cleaned up"
        end 
      end
    end
    if !app_created
      unless @gitrepo.blank?
        @gitrepo = @gitrepo.strip
        if Utils::GitUtil.git_uri_valid?(@gitrepo)
          begin
            @gitbranch = @gitbranch.blank? ? "master" : @gitbranch.strip
            app = App.new(@cf_client)
            app.upload_app_from_git(@name, @gitrepo, @gitbranch)
            flash[:notice] = I18n.t('apps.controller.app_created_bits_uploaded', :name => @name)
          rescue Exception => ex
            flash[:notice] = I18n.t('apps.controller.app_created_no_bits', :name => @name, :msg => ex.message)
          end
        else
          flash[:notice] = I18n.t('apps.controller.app_created_no_bits', :name => @name, :msg => "Invalid Git Repository URI.")
        end
      end
    end
    logger.info "end"
    respond_to do |format|
      format.html { redirect_to apps_info_url }
      format.js { flash.discard }
    end
  end

  def show
    @name = params[:name]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
      redirect_to apps_info_url
    else
      begin
        @name = @name.strip
        app = App.new(@cf_client)
        @app = app.find(@name)
        @app[:instances_info] = Utils::FiberedIterator.map(@app[:instances_info], configatron.reactor_iterator.concurrency) do |instance|
          instance[:stats].nil? ? instance[:logfiles] = [] : instance[:logfiles] = find_log_files(@name, instance[:instance])
          instance
        end
        @app[:services] = Utils::FiberedIterator.map(@app[:services], configatron.reactor_iterator.concurrency) do |service|
          find_service_details(service)
        end
        @app_files = find_files(@name, "/")
        @available_instances = find_available_instances(@app[:state], @app[:resources][:memory], @app[:instances])
        @available_memsizes = find_available_memsizes(@app[:state], @app[:resources][:memory], @app[:instances])
        @available_services = find_available_services()
      rescue CloudFoundry::Client::Exception::NotFound => ex
        flash[:alert] = ex.message
        redirect_to apps_info_url
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
  end

  def start(appname = nil)
    @name = appname || params[:name]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    else
      begin
        @name = @name.strip 
        app = App.new(@cf_client)
        @updated_app = [] << app.start(@name)
        @updated_app.collect! { |app_info| app.find(@name)}
        flash[:notice] = I18n.t('apps.controller.app_started', :name => @name)
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    respond_to do |format|
      format.html { redirect_to apps_info_url }
      format.js { flash.discard }
    end
  end

  def stop
    @name = params[:name]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    else
      begin
        @name = @name.strip
        app = App.new(@cf_client)
        @updated_app = [] << app.stop(@name)
        @updated_app.collect! { |app_info| app.find(@name)}
        flash[:notice] = I18n.t('apps.controller.app_stopped', :name => @name)
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    respond_to do |format|
      format.html { redirect_to apps_info_url }
      format.js { flash.discard }
    end
  end

  def restart
    @name = params[:name]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    else
      begin
        @name = @name.strip
        app = App.new(@cf_client)
        @updated_app = [] << app.restart(@name)
        @updated_app.collect! { |app_info| app.find(@name)}
        flash[:notice] = I18n.t('apps.controller.app_restarted', :name => @name)
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    respond_to do |format|
      format.html { redirect_to apps_info_url }
      format.js { flash.discard }
    end
  end

  def delete
    @name = params[:name]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    else
      begin
        @name = @name.strip
        app = App.new(@cf_client)
        app.delete(@name)
        flash[:notice] = I18n.t('apps.controller.app_deleted', :name => @name)
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    respond_to do |format|
      format.html { redirect_to apps_info_url }
      format.js { flash.discard }
    end
  end

  def set_instances
    @name = params[:name]
    @instances = params[:instances]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    elsif @instances.blank?
      flash[:alert] = I18n.t('apps.controller.instances_blank')
    else
      begin
        @name = @name.strip
        app = App.new(@cf_client)
        app.set_instances(@name, @instances)
        flash[:notice] = I18n.t('apps.controller.instances_set', :instances => @instances)
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    respond_to do |format|
      format.html { redirect_to app_info_url(@name) }
      format.js {
        if flash[:alert]
          render "apps/resources/set_instances", :status => :bad_request
        else
          render "apps/resources/set_instances"
        end
        flash.discard
      }
    end
  end

  def set_memsize
    @name = params[:name]
    @memsize = params[:memsize]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    elsif @memsize.blank?
      flash[:alert] = I18n.t('apps.controller.memsize_blank')
    else
      begin
        @name = @name.strip
        app = App.new(@cf_client)
        app.set_memsize(@name, @memsize)
        flash[:notice] = I18n.t('apps.controller.memsize_set', :memsize => @memsize)
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    respond_to do |format|
      format.html { redirect_to app_info_url(@name) }
      format.js {
        if flash[:alert]
          render "apps/resources/set_memsize", :status => :bad_request
        else
          render "apps/resources/set_memsize"
        end
        flash.discard
      }
    end
  end

  def set_var
    @name    = params[:name]
    @edit    = params[:edit]
    @restart = params[:restart]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    else
      if @edit.nil?
        @var_name = params[:var_name]
      else
        envvar, @var_name = params[:id].split("-envvar-")
      end
      if @var_name.blank?
       flash[:alert] = I18n.t('apps.controller.varname_blank')
      else
        begin
          @name = @name.strip
          @var_name = @var_name.strip.upcase
          @var_value = params[:var_value]
          app = App.new(@cf_client)
          @var_exists = app.set_var(@name, @var_name, @var_value, @restart)
          @new_var = [] << {:var_name => @var_name, :var_value => @var_value}
          flash[:notice] = I18n.t('apps.controller.envvar_set', :var_name => @var_name)
        rescue Exception => ex
          flash[:alert] = ex.message
        end
      end
    end
    respond_to do |format|
      format.html { redirect_to app_info_url(@name) }
      format.js {
        if flash[:alert] && !@edit.nil?
          render "apps/envvars/set_var", :status => :bad_request
        else
          render "apps/envvars/set_var"
        end
        flash.discard
      }
    end
  end

  def unset_var
    @name = params[:name]
    @var_name = params[:var_name]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    elsif @var_name.blank?
      flash[:alert] = I18n.t('apps.controller.varname_blank')
    else
      begin
        @name = @name.strip
        @var_name = @var_name.strip.upcase
        app = App.new(@cf_client)
        app.unset_var(@name, @var_name)
        flash[:notice] = I18n.t('apps.controller.envvar_unset', :var_name => @var_name)
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    respond_to do |format|
      format.html { redirect_to app_info_url(@name) }
      format.js {
        render "apps/envvars/unset_var"
        flash.discard
      }
    end
  end

  def bind_service
    @name = params[:name]
    @service = params[:service]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    elsif @service.blank?
      flash[:alert] = I18n.t('apps.controller.service_blank')
    else
      begin
        @name = @name.strip
        app = App.new(@cf_client)
        app.bind_service(@name, @service)
        @new_service = [] << find_service_details(@service)
        flash[:notice] = I18n.t('apps.controller.service_binded', :service => @service)
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    respond_to do |format|
      format.html { redirect_to app_info_url(@name) }
      format.js {
        render "apps/services/bind_service"
        flash.discard
      }
    end
  end

  def unbind_service
    @name = params[:name]
    @service = params[:service]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    elsif @service.blank?
      flash[:alert] = I18n.t('apps.controller.service_blank')
    else
      begin
        @name = @name.strip
        app = App.new(@cf_client)
        app.unbind_service(@name, @service)
        flash[:notice] = I18n.t('apps.controller.service_unbinded', :service => @service)
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    respond_to do |format|
      format.html { redirect_to app_info_url(@name) }
      format.js {
        render "apps/services/unbind_service"
        flash.discard
      }
    end
  end

  def map_url
    @name = params[:name]
    @url = params[:url]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    elsif @url.blank?
      flash[:alert] = I18n.t('apps.controller.url_blank')
    else
      begin
        @name = @name.strip
        @url = @url.strip.gsub(/^http(s*):\/\//i, '').downcase
        app = App.new(@cf_client)
        @new_url = [] << app.map_url(@name, @url)
        flash[:notice] = I18n.t('apps.controller.url_mapped', :url => @url)
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    respond_to do |format|
      format.html { redirect_to app_info_url(@name) }
      format.js {
        render "apps/urls/map_url"
        flash.discard
      }
    end
  end

  def unmap_url
    @name = params[:name]
    @url = params[:url]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    elsif @url.blank?
      flash[:alert] = I18n.t('apps.controller.url_blank')
    else
      begin
        @name = @name.strip
        @url = @url.strip.gsub(/^http(s*):\/\//i, '').downcase
        app = App.new(@cf_client)
        app.unmap_url(@name, @url)
        @url_hash = @url.hash.to_s
        flash[:notice] = I18n.t('apps.controller.url_unmapped', :url => @url)
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    respond_to do |format|
      format.html { redirect_to app_info_url(@name) }
      format.js {
        render "apps/urls/unmap_url"
        flash.discard
      }
    end
  end

  def update_bits
    @name = params[:name]
    @deployform = params[:deployform]
    @gitrepo = params[:gitrepo]
    @gitbranch = params[:gitbranch]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    elsif @gitrepo.blank?
      flash[:alert] = I18n.t('apps.controller.gitrepo_blank')
    else
      @name = @name.strip
      @gitrepo = @gitrepo.strip
      if Utils::GitUtil.git_uri_valid?(@gitrepo)
        begin
          @gitbranch = @gitbranch.blank? ? "master" : @gitbranch.strip
          app = App.new(@cf_client)
          app.upload_app_from_git(@name, @gitrepo, @gitbranch)
          flash[:notice] = I18n.t('apps.controller.bits_uploaded')
        rescue Exception => ex
          flash[:alert] = ex.message
        end
      else
        flash[:alert] = I18n.t('apps.controller.gitrepo_invalid')
      end
    end
    respond_to do |format|
      format.html { redirect_to apps_info_url }
      format.js { flash.discard }
    end
  end

  def download_bits
    @name = params[:name]
    bits_sended = false
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    else
      begin
        app = App.new(@cf_client)
        zipfile = app.download_app(@name)
        send_file(zipfile, :type=>"application/zip")
        bits_sended = true
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    unless bits_sended
      respond_to do |format|
        format.html { redirect_to app_info_url(@name) }
      end
    end
  ensure
    # TODO Need to delete the zipfile in a delayed job
    # FileUtils.rm_f(zipfile) if zipfile
  end

  def files
    @name = params[:name]
    @instance = params[:instance] || 0
    @filename = params[:filename]
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    elsif @filename.blank?
      flash[:alert] = I18n.t('apps.controller.filename_blank')
    else
      @name = @name.strip
      @filename = Base64.decode64(@filename)
      begin
        @app_files = find_files(@name, @filename, @instance)
      rescue Exception => ex
        flash[:alert] = ex.message
      end
    end
    respond_to do |format|
      format.html { redirect_to app_info_url(@name) }
      format.js {
        render "apps/files/files"
        flash.discard
      }
    end
  end

  def view_file
    @name = params[:name]
    @instance = params[:instance] || 0
    @filename = params[:filename]
    @formatcode = params[:formatcode] || "true"
    if @name.blank?
      flash[:alert] = I18n.t('apps.controller.name_blank')
    elsif @filename.blank?
      flash[:alert] = I18n.t('apps.controller.filename_blank')
    else
      @name = @name.strip
      @filename = Base64.decode64(@filename)
      begin
        app = App.new(@cf_client)
        contents = app.view_file(@name, @filename, @instance)
        if is_binary?(contents)
          flash[:alert] = I18n.t('apps.controller.file_binary')
        else
          if @formatcode == "true"
            lang = CodeRay::FileType[@filename]
            code = CodeRay.scan(contents, lang)
            @file_contents = code.html(:line_numbers => :table)
            @file_loc = code.loc
          else
            @file_contents = contents.split("\n")
          end
        end
      rescue Exception => ex
        flash[:alert] = I18n.t('apps.controller.file_not_found')
      end
    end
    respond_to do |format|
      format.html {
        render "apps/files/app_view_file", :layout => false
      }
      format.js {
        render "apps/files/view_file"
        flash.discard
      }
    end
  end

  private

  def find_available_frameworks_runtimes()
    available_frameworks = []
    system = System.new(@cf_client)
    frameworks = system.find_all_frameworks()
    if frameworks.empty?
      available_frameworks << [I18n.t('apps.controller.no_frameworks'), ""]
    else
      available_frameworks << [I18n.t('apps.controller.select_framework'), ""]
      frameworks.each do |fwk_name, fwk|
        fwk[:runtimes].each do |run|
          available_frameworks << [fwk[:name].capitalize + " " + I18n.t('apps.controller.fwk_on_run') + " " + run[:description], fwk_name.to_s + "/" + run[:name].to_s]
        end
      end
    end
    available_frameworks
  end

  def find_available_instances(app_state, app_memsize, app_instances)
    system = System.new(@cf_client)
    available_for_use = system.find_available_memory()
    if app_state != 'STOPPED'
      available_for_use = available_for_use + (app_memsize.to_i * app_instances.to_i)
    end
    available_instances = available_for_use.to_i / app_memsize.to_i
  end

  def find_available_memsizes(app_state, app_memsize, app_instances)
    system = System.new(@cf_client)
    available_for_use = system.find_available_memory()
    if app_state != 'STOPPED'
      available_for_use = available_for_use + (app_memsize.to_i * app_instances.to_i)
    end

    available_memsizes = {}
    available_memsizes[64] = "64 Mb" if available_for_use >= (64 * app_instances.to_i)
    available_memsizes[128] = "128 Mb" if available_for_use >= (128 * app_instances.to_i)
    available_memsizes[256] = "256 Mb" if available_for_use >= (256 * app_instances.to_i)
    available_memsizes[512] = "512 Mb" if available_for_use >= (512 * app_instances.to_i)
    available_memsizes[1024] = "1 Gb" if available_for_use >= (1024 * app_instances.to_i)
    available_memsizes[2048] = "2 Gb" if available_for_use >= (2048 * app_instances.to_i)
    if available_memsizes.empty?
      available_memsizes[""] = I18n.t('apps.controller.no_memory')
    else
      if app_memsize > 0
        available_memsizes["selected"] = app_memsize
      end
    end
    available_memsizes
  end

  def find_available_services
    available_services = []
    service = Service.new(@cf_client)
    provisioned_services = service.find_all_services()
    if provisioned_services.empty?
      available_services << [I18n.t('apps.controller.no_services'), ""]
    else
      available_services << [I18n.t('apps.controller.select_service'), ""]
      provisioned_services.each do |service_info|
        available_services << [service_info[:name] + " (" + service_info[:vendor] + " " + service_info[:version] + ")", service_info[:name]]
      end
    end
    available_services
  end

  def find_files(name, path, instance = 0)
    files = []
    begin
      app = App.new(@cf_client)
      contents = app.view_file(name, path, instance)
    rescue Exception => ex
      contents = ""
    end
    lines = contents.split("\n")
    lines.each do |line|
      filename = line.match('^[^ ]*')
      filesize = line.match('[^ ]*$')
      if filename.to_s.match('/$').nil?
        filetype = "file"
      else
        filetype = "dir"
      end
      files << {:name => filename.to_s, :size => filesize.to_s, :type => filetype, :path => path}
    end
    files
  end

  def find_log_files(name, instance)
    instance_logs = []
    logfiles = find_files(name, "/logs", instance.to_i)
    unless logfiles.empty?
      %w(stdout.log stderr.log startup.log err.log staging.log migration.log).each do |log|
        logfiles.each do |logfile|
          if logfile[:name] == log && logfile[:size] != "0B"
            name = logfile[:name].split(".")
            instance_logs << {:name => name[0], :path => "logs/" + logfile[:name]}
            break
          end
        end
      end
    end
    instance_logs
  end

  def find_service_details(name)
    service = Service.new(@cf_client)
    service_details = service.find(name)
    if service_details.empty?
      return {:name => name, :vendor => "", :version => "" }
    else
      return {:name => name, :vendor => service_details[:vendor], :version => service_details[:version] }
    end
  end

  def is_binary?(string)
    string.each_byte do |x|
      x.nonzero? or return true
    end
    false
  end
##handle apps deployment
  def detect_framework(path, selected_framework)
    if !File.directory? path
      if path.to_s.end_with?('.war')
        detect_framework_from_war path, selected_framework
      elsif path.to_s.end_with?('.zip')
        detect_framework_from_zip path, selected_framework
      elsif selected_framework == "standalone"
        return true
      else
        return nil
      end
    end
  end

  def detect_framework_from_war(war_file=nil, framework)
    if war_file
      contents = ZipUtil.entry_lines(war_file)
    else
    #assume we are working with current dir
      contents = Dir['**/*'].join("\n")
    end

    # Spring/Lift Variations
    # Grails
    if contents =~ /WEB-INF\/lib\/grails-web.*\.jar/ && framework != "grails"
        raise I18n.t('apps.controller.app_framework_detect', :frame_type => "grails")
    # Lift
    elsif contents =~ /WEB-INF\/lib\/lift-webkit.*\.jar/ && framework != "lift"
        raise I18n.t('apps.controller.app_framework_detect', :frame_type => "lift")
    # Spring
    elsif contents =~ /WEB-INF\/classes\/org\/springframework/ && framework != "spring"
        raise I18n.t('apps.controller.app_framework_detect', :frame_type => "spring")
    # Spring
    elsif contents =~ /WEB-INF\/lib\/spring-core.*\.jar/ && framework != "spring"
        raise I18n.t('apps.controller.app_framework_detect', :frame_type => "spring")
    # Spring
    elsif contents =~ /WEB-INF\/lib\/org\.springframework\.core.*\.jar/ && framework != "spring" 
        raise I18n.t('apps.controller.app_framework_detect', :frame_type => "spring")
    # JavaWeb
    else
      if framework != "java_web" || framework != "java_web_tongweb"
        raise I18n.t('apps.controller.app_framework_detect', :frame_type => "java_web")
      end
    end
  end

  def detect_framework_from_zip(zip_file, framework)
    contents = ZipUtil.entry_lines(zip_file)
    detect_framework_from_zip_contents(contents, zip_file, framework)
  end

  def detect_framework_from_zip_contents(contents, zip_file, framework)
    if contents =~ /lib\/play\..*\.jar/ && framework != "play"
        raise I18n.t('apps.controller.app_framework_detect', :frame_type => "play")
    elsif framework == "standalone"
      return true
    else
    #unpack zip and detect the framework
      if zip_file
        dir = File.dirname(zip_file.to_s)
        filename = File.basename(zip_file.to_s, ".zip")
        dest_dir = dir + "/" + filename
        ZipUtil.unpack(zip_file, dest_dir)
        if File.directory? dest_dir
          Dir.chdir(dest_dir) do
          # Rails
            if File.exist?('config/environment.rb') && framework != "rails3"
              raise I18n.t('apps.controller.app_framework_detect', :frame_type => "rails3")

            # Rack
            elsif File.exist?('config.ru') && framework != "rack"
              raise I18n.t('apps.controller.app_framework_detect', :frame_type => "rack")

            # Java Web Apps
            elsif File.exist?('WEB-INF/web.xml')
              return detect_framework_from_war(nil, framework)

            # Simple Ruby Apps
            elsif !Dir.glob('*.rb').empty?
              matched_file = nil
              Dir.glob('*.rb').each do |fname|
                next if matched_file
                File.open(fname, 'r') do |f|
                  str = f.read # This might want to be limited
                  matched_file = fname if (str && str.match(/^\s*require[\s\(]*['"]sinatra['"]/))
                end
              end
              if matched_file
                # Sinatra apps
                if framework != "sinatra"
                  raise I18n.t('apps.controller.app_framework_detect', :frame_type => "sinatra")
                end
                return {:exec => "ruby #{matched_file}"}
              end

            # PHP
            elsif !Dir.glob('*.php').empty? && framework != "php"
              raise I18n.t('apps.controller.app_framework_detect', :frame_type => "php")

            # Erlang/OTP using Rebar
            elsif !Dir.glob('releases/*/*.rel').empty? && !Dir.glob('releases/*/*.boot').empty? && framework != "otp_rebar"
              raise I18n.t('apps.controller.app_framework_detect', :frame_type => "otp_rebar")

            # Python Django
            # XXX: not all django projects keep settings.py in top-level directory
            elsif File.exist?('manage.py') && File.exist?('settings.py') && framework != "django"
              raise I18n.t('apps.controller.app_framework_detect', :frame_type => "django")

            # Python wsgi
            elsif !Dir.glob('wsgi.py').empty? && framework != "wsgi"
              raise I18n.t('apps.controller.app_framework_detect', :frame_type => "wsgi")

            # .Net
            elsif !Dir.glob('web.config').empty? && framework != "dotnet"
              raise I18n.t('apps.controller.app_framework_detect', :frame_type => "dotnet")

            # Node.js
            elsif !Dir.glob('*.js').empty?
              if File.exist?('server.js') || File.exist?('app.js') || File.exist?('index.js') || File.exist?('main.js')
                if framework != "node"
                  raise I18n.t('apps.controller.app_framework_detect', :frame_type => "node")
                end
              end
            end
          end
        end
      end
    end
  end
  
  def check_unreachable_links(path)
      files = Dir.glob("#{path}/**/*", File::FNM_DOTMATCH)

      pwd = Pathname.pwd

      abspath = File.expand_path(path)
      unreachable = []
      files.each do |f|
        file = Pathname.new(f)
        if file.symlink? && !file.realpath.to_s.start_with?(abspath)
          unreachable << file.relative_path_from(pwd)
        end
      end

      unless unreachable.empty?
        root = Pathname.new(path).relative_path_from(pwd)
        err "Can't deploy application containing links '#{unreachable}' that reach outside its root '#{root}'"
      end
    end

    def find_sockets(path)
      files = Dir.glob("#{path}/**/*", File::FNM_DOTMATCH)
      files && files.select { |f| File.socket? f }
    end
  #upload application file to cloudfoundry
  def upload_app_bits2cf(appname, path, manifest)
      logger.info 'Uploading Application:'
      
      upload_file, file = "#{Dir.tmpdir}/#{appname}", nil
      Utils::FileUtilsAsync.rm_f(upload_file)

      explode_dir = "#{Dir.tmpdir}/.cf_#{appname}_files"
      Utils::FileUtilsAsync.rm_rf(explode_dir) # Make sure we didn't have anything left over..

      if path.to_s =~ /\.(war|zip)$/
        #single file that needs unpacking
        ZipUtil.unpack(path, explode_dir)
      elsif path.to_s =~ /\.tar.gz$/
        Utils::CFCTAR.extract(path, explode_dir)   
      elsif !File.directory? path
        #single file that doesn't need unpacking
        Utils::FileUtilsAsync.mkdir(explode_dir)
        Utils::FileUtilsAsync.cp(path, explode_dir)
      else
        Dir.chdir(path) do
          # Stage the app appropriately and do the appropriate fingerprinting, etc.
          if war_file = Dir.glob('*.war').first
            VMC::Cli::ZipUtil.unpack(war_file, explode_dir)
          elsif zip_file = Dir.glob('*.zip').first
            VMC::Cli::ZipUtil.unpack(zip_file, explode_dir)
          else
            check_unreachable_links(path)
            Utils::FileUtilsAsync.mkdir(explode_dir)

            files = Dir.glob('{*,.[^\.]*}')

            # Do not process .git files
            files.delete('.git') if files

            Utils::FileUtilsAsync.cp_r(files, explode_dir)

            find_sockets(explode_dir).each do |s|
              File.delete s
            end
          end
        end
      end

      # Send the resource list to the cloudcontroller, the response will tell us what it already has..
      unless nil
        logger.info '  Checking for available resources: '
        fingerprints = []
        total_size = 0
        resource_files = Dir.glob("#{explode_dir}/**/*", File::FNM_DOTMATCH)
        resource_files.each do |filename|
          next if (File.directory?(filename) || !File.exists?(filename))
          fingerprints << {
            :size => File.size(filename),
            :sha1 => Digest::SHA1.file(filename).hexdigest,
            :fn => filename
          }
          total_size += File.size(filename)
        end

        # Check to see if the resource check is worth the round trip
        if (total_size > (64*1024)) # 64k for now
          # Send resource fingerprints to the cloud controller
          appcloud_resources = @cf_client.check_resources(fingerprints)
        end
        logger.info "check_resources OK"

        if appcloud_resources
          logger.info '  Processing resources: '
          # We can then delete what we do not need to send.
          appcloud_resources.each do |resource|
            Utils::FileUtilsAsync.rm_f resource[:fn]
            # adjust filenames sans the explode_dir prefix
            resource[:fn].sub!("#{explode_dir}/", '')
          end
        end
      end

      # If no resource needs to be sent, add an empty file to ensure we have
      # a multi-part request that is expected by nginx fronting the CC.
      #if ZipUtil.get_files_to_pack(explode_dir).empty?
        Dir.chdir(explode_dir) do
          Utils::FileUtilsAsync.new(".__empty__", "w")
        end
      #end
      logger.info "dir #{explode_dir}"
      # Perform Packing of the upload bits here.
      logger.info  '  Packing application: '
      ZipUtil.pack(explode_dir, upload_file)
      logger.info 'Packing application complete'

      upload_size = File.size(upload_file);
      if upload_size > 1024*1024
        upload_size  = (upload_size/(1024.0*1024.0)).round.to_s + 'M'
      elsif upload_size > 0
        upload_size  = (upload_size/1024.0).round.to_s + 'K'
      else
        upload_size = '0K'
      end
 
      logger.info "Appname: #{appname}, File: #{upload_file}"
      
      app = App.new(@cf_client)
      app.upload_app_async(appname, upload_file) 
      logger.info "Upload of #{appname} Complete"  
      
      
      ensure
        # Cleanup if we created an exploded directory.
        Utils::FileUtilsAsync.rm_f(upload_file) if upload_file
        Utils::FileUtilsAsync.rm_rf(explode_dir) if explode_dir
    end
end

