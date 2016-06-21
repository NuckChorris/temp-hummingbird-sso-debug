after_initialize do
  class SessionController < ApplicationController
    def sso_login
      unless SiteSetting.enable_sso
        return render(nothing: true, status: 404)
      end
  
      sso = DiscourseSingleSignOn.parse(request.query_string)
      if !sso.nonce_valid?
        if SiteSetting.verbose_sso_logging
          Rails.logger.warn("Verbose SSO log: Nonce has already expired\n\n#{sso.diagnostics}")
        end
        return render(text: I18n.t("sso.timeout_expired"), status: 419)
      end
  
      if ScreenedIpAddress.should_block?(request.remote_ip)
        if SiteSetting.verbose_sso_logging
          Rails.logger.warn("Verbose SSO log: IP address is blocked #{request.remote_ip}\n\n#{sso.diagnostics}")
        end
        return render(text: I18n.t("sso.unknown_error"), status: 500)
      end
  
      return_path = sso.return_path
      sso.expire_nonce!
  
      begin
        if user = sso.lookup_or_create_user(request.remote_ip)
  
          if SiteSetting.must_approve_users? && !user.approved?
            if SiteSetting.sso_not_approved_url.present?
              redirect_to SiteSetting.sso_not_approved_url
            else
              render text: I18n.t("sso.account_not_approved"), status: 403
            end
            return
          elsif !user.active?
            activation = UserActivator.new(user, request, session, cookies)
            activation.finish
            session["user_created_message"] = activation.message
            redirect_to users_account_created_path and return
          else
            if SiteSetting.verbose_sso_logging
              Rails.logger.warn("Verbose SSO log: User was logged on #{user.username}\n\n#{sso.diagnostics}")
            end
            log_on_user user
          end
  
          # If it's not a relative URL check the host
          if return_path !~ /^\/[^\/]/
            begin
              uri = URI(return_path)
              return_path = path("/") unless uri.host == Discourse.current_hostname
            rescue
              return_path = path("/")
            end
          end
  
          redirect_to return_path
        else
          render text: I18n.t("sso.not_found"), status: 500
        end
      rescue => e
        message = "Failed to create or lookup user: #{e}."
        message << "\n\n" << "-" * 100 << "\n\n"
        message << sso.diagnostics
        message << "\n\n" << "-" * 100 << "\n\n"
        message << e.backtrace.join("\n")
  
        Rails.logger.error(message)
  
        render text: I18n.t("sso.unknown_error"), status: 500
      end
    end
  end
end
