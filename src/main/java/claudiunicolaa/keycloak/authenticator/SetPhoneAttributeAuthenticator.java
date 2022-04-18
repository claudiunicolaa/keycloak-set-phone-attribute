package claudiunicolaa.keycloak.authenticator;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.Response;
import java.util.Collections;

@JsonIgnoreProperties(value = {"required"})
class TwoFactorAuthAttribute {
	String type;

	public void setType(String type) {
		this.type = type;
	}

	public boolean isSmsType() {
		return type.equals("sms");
	}

	public boolean isAppType() {
		return type.equals("app");
	}
}

/**
 * @author Claudiu Nicola, https://claudiunicola.xyz, @claudiunicolaa
 */
public class SetPhoneAttributeAuthenticator implements Authenticator {

	private static final String TPL_CODE = "login-update-phone.ftl";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		UserModel user = context.getUser();
		String twoFactorAuthAttr = user.getFirstAttribute("two_factor_auth");
		// skip if the attribute doesn't exist
		if (twoFactorAuthAttr == null) {
			context.success();
			return;
		}

		try {
			TwoFactorAuthAttribute twoFactorAuth = JsonSerialization.readValue(twoFactorAuthAttr, TwoFactorAuthAttribute.class);
			// show form only if the two-factor auth is via SMS and the user has not the phone attribute set
			if (twoFactorAuth.isSmsType() && user.getFirstAttribute("phone") == null) {
				context.challenge(
					context.form()
						.setAttribute("realm", context.getRealm())
						.createForm(TPL_CODE)
				);
				return;
			}
			context.success();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		EventBuilder event = context.getEvent()
			.event(EventType.UPDATE_PROFILE)
			.detail(Details.ACTION, "set-phone-attribute");
		EventBuilder errorEvent = event.clone()
			.event(EventType.UPDATE_PROFILE_ERROR)
			.detail(Details.ACTION, "set-phone-attribute")
			.client(authSession.getClient())
			.user(authSession.getAuthenticatedUser());

		String enteredPhone = context.getHttpRequest().getDecodedFormParameters().getFirst("phone");

		if (enteredPhone == null || !isValidPhone(enteredPhone)) {
			Response challenge = context.form()
				.setAttribute("phone", enteredPhone)
				.addError(new FormMessage("phone", "phoneAuthInvalid"))
				.createForm(TPL_CODE);
			context.challenge(challenge);
			errorEvent.error("invalid_phone");
			return;
		}

		context.getUser().setAttribute("phone", Collections.singletonList(enteredPhone));
		context.success();

		event.user(context.getUser())
			.detail("phone", enteredPhone)
			.success();
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}

	private boolean isValidPhone(String phone) {
		Phonenumber.PhoneNumber phoneProto;
		try {
			phoneProto = PhoneNumberUtil.getInstance().parse(phone, null);
		} catch (NumberParseException e) {
			return false;
		}
		return PhoneNumberUtil.getInstance().isValidNumber(phoneProto);
	}
}
