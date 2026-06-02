var close_animate=true, on_page=20,off=0;
function ct_getCookie(name) {
	var matches = document.cookie.match(new RegExp(
		"(?:^|; )" + name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, '\\$1') + "=([^;]*)"
	));
	return matches ? decodeURIComponent(matches[1]) : undefined;
}

function ct_setCookie(name, value){
	var domain=location.hostname;
	tmp=domain.split('.');
	if(tmp[0].toLowerCase()=='www')
		tmp[0]='';
	else
		tmp[0]='.'+tmp[0];
	domain=tmp.join('.');

	document.cookie = name+" =; expires=Thu, 01 Jan 1970 00:00:01 GMT; path = /";
	document.cookie = name+" =; expires=Thu, 01 Jan 1970 00:00:01 GMT";
	document.cookie = name+" =; expires=Thu, 01 Jan 1970 00:00:01 GMT; path = /; domain = " +  domain;

	var date = new Date;
	date.setDate(date.getDate() + 365);
	setTimeout(function() { document.cookie = name+"=" + value + "; expires=" + date.toUTCString() + "; path = /;"}, 200)
}

function animate_banner(to){
	if(close_animate){
		jQuery('#feedback_notice').fadeTo(300,to);
	}
}

function ctAdminRequest(data, onSuccess, onError) {
	Joomla.request({
		url: location.href,
		method: 'POST',
		data: jQuery.param(data),
		headers: {
			'Cache-Control': 'no-cache'
		},
		onSuccess: onSuccess || function () {},
		onError: onError || function (xhr) {
			jQuery('#ct_preloader, #ct_preloader_spam_results').hide();
			console.error('CleanTalk admin request failed:', (xhr && xhr.status) ? xhr.status : xhr);
		}
	});
}
}

function ctEscapeHtml(text) {
	return jQuery('<div>').text(text == null ? '' : String(text)).html();
}

function ctGetBlockTemplate(blockKey) {
	var templates = {
		plain_message: '<center><h2>{message}</h2></center>',

		spam_comments_toolbar:
			"<button id='delete_all_spam_comments' class='btn btn-danger' onclick='delete_comment(true)' type='button'>{delall}</button>" +
			"<button id='delete_sel_spam_comments' class='btn btn-danger' onclick='delete_comment()' type='button'>{delsel}</button>",

		spam_comments_table_open:
			'<center><table id="spamcomments_table" class="table table-bordered table-hover table-striped" cellspacing="0" cellpadding="3">' +
			'<thead><tr><th></th><th>{username_label}</th><th>{email_label}</th><th>{text_label}</th><th>{date_label}</th></tr></thead><tbody>',

		spam_comments_table_close: '</tbody></table></center>',

		spam_comment_row:
			"<tr>" +
			"<td><input type='checkbox' name='ct_del_comment[{id}]' value='1' /></td>" +
			"<td>{username}</td>" +
			"<td><a target='_blank' rel='noopener noreferrer' href='{email_href}'>{email}</a></td>" +
			"<td>{comment}</td>" +
			"<td>{date}</td>" +
			"</tr>",

		spam_load_more:
			"<center><button id='load_more_results' class='btn btn-default' onclick='load_more()' type='button'>{label}</button></center>",

		connection_reports_table_open:
			'<center><table id="connection_reports_table" class="table table-bordered table-hover table-striped" cellspacing="0" cellpadding="3">' +
			'<thead><tr><th>{date_label}</th><th>{pageurl_label}</th><th>{libreport_label}</th></tr></thead><tbody>',

		connection_report_row:
			'<tr><td>{date}</td><td>{page_url}</td><td>{lib_report}</td></tr>',

		connection_reports_table_close: '</tbody></table></center>',

		connection_report_send_button:
			"<button id='send_connection_report' class='btn btn-success' type='button'>{label}</button>"
	};

	return templates[blockKey] || '';
}

function ctRenderBlock(blockKey, item) {
	item = item || {};
	var template = ctGetBlockTemplate(blockKey);
	var data = {};

	switch (blockKey) {
		case 'plain_message':
			data.message = ctEscapeHtml(item.message);
			break;

		case 'spam_comments_toolbar':
			data.delall = ctEscapeHtml(ct_spamcheck_delall);
			data.delsel = ctEscapeHtml(ct_spamcheck_delsel);
			break;

		case 'spam_comments_table_open':
			data.username_label = ctEscapeHtml(ct_spamcheck_table_username);
			data.email_label = ctEscapeHtml(ct_spamcheck_table_email);
			data.text_label = ctEscapeHtml(ct_spamcheck_table_text);
			data.date_label = ctEscapeHtml(ct_spamcheck_table_date);
			break;

		case 'spam_comment_row':
			data.id = ctEscapeHtml(item.id);
			data.username = ctEscapeHtml(item.username);
			data.email = ctEscapeHtml(item.email);
			data.email_href = ctEscapeHtml(
				'https://cleantalk.org/blacklists/' + encodeURIComponent(item.email == null ? '' : String(item.email))
			);
			data.comment = ctEscapeHtml(item.comment);
			data.date = ctEscapeHtml(item.date);
			break;

		case 'spam_load_more':
			data.label = ctEscapeHtml(ct_spamcheck_load_more_results);
			break;

		case 'connection_reports_table_open':
			data.date_label = ctEscapeHtml(ct_connection_reports_table_date);
			data.pageurl_label = ctEscapeHtml(ct_connection_reports_table_pageurl);
			data.libreport_label = ctEscapeHtml(ct_connection_reports_table_libreport);
			break;

		case 'connection_report_row':
			data.date = ctEscapeHtml(item.date);
			data.page_url = ctEscapeHtml(item.page_url);
			data.lib_report = ctEscapeHtml(item.lib_report);
			break;

		case 'connection_report_send_button':
			data.label = ctEscapeHtml(ct_connection_reports_send_report);
			break;
	}

	return template.replace(/\{(\w+)\}/g, function (match, key) {
		return Object.prototype.hasOwnProperty.call(data, key) ? data[key] : '';
	});
}

function ctAppendBlock(container, blockKey, item) {
	jQuery(container).append(ctRenderBlock(blockKey, item));
}

function ctAppendPlainMessage(container, text) {
	ctAppendBlock(container, 'plain_message', { message: text });
}

// Get system messages and handle these
document.addEventListener('DOMContentLoaded', () => {
	setTimeout(dispatchJoomlaNotices, 0);
});
function dispatchJoomlaNotices() {
	const joomlaAlertWrapper = document.getElementById("system-message-container");
	if ( joomlaAlertWrapper !== null ) {
		let joomlaAlerts = joomlaAlertWrapper.getElementsByTagName('joomla-alert');
		if ( joomlaAlerts.length === 0 ) {
			joomlaAlerts = joomlaAlertWrapper.getElementsByClassName('alert');
		}
		if ( joomlaAlerts.length > 0 ) {
			for ( let i = 0; i < joomlaAlerts.length; i++ ) {
				dispatchApbctJoomlaNotice(joomlaAlerts[i]);
			}
		}
	}
}
function dispatchApbctJoomlaNotice(element) {
	const apbctNotice = element.querySelector("#apbct_joomla_notice");
	let oldWay = element.tagName !== 'JOOMLA-ALERT';

	if ( apbctNotice !== null ) {
		// Disable notice dismissing on the plugin settings page
		const currentUrl = new URL(location.href);
		if ( currentUrl.searchParams.get('layout') === 'edit' && +currentUrl.searchParams.get('extension_id') === ct_extension_id ) {
			if ( typeof element.destroyCloseButton === "function" ) {
				element.destroyCloseButton();
			} else {
				element.getElementsByClassName('close')[0].remove();
			}
		}

		// Listen close event only on the TRIAL of RENEW banner
		if ( apbctNotice.dataset.noticeType === 'trial' || apbctNotice.dataset.noticeType === 'renew' ) {
			const dispatchedElement = oldWay ? element.getElementsByClassName('close')[0] : element;
			const dispatchedEvent = oldWay ? 'click' : 'joomla.alert.close';

			if ( typeof dispatchedElement === 'undefined' ) {
				return;
			}

			dispatchedElement.addEventListener(dispatchedEvent, (event) => {
				let data = {
					'action' : 'dismiss_notice',
					'data': {
						'notice_type' : apbctNotice.dataset.noticeType
					}
				};
				Joomla.request({
					url: 'index.php?option=com_ajax&plugin=cleantalkantispam&format=json',
					method: 'POST',
					data: JSON.stringify(data),
					headers: {
						'Cache-Control' : 'no-cache'
					},
					onSuccess: function (response, xhr){
						try {
							let responseData = JSON.parse(response);
							responseData = responseData.data[0];
							if ( responseData.error ) {
								// Do something with the error
							} else {
								// Do something with the regular result
							}
						} catch (e) {
							console.log(e.toString());
							console.log(e.fileName);
							console.log(e.lineNumber);
						}
					}
				});
			});
		}
	}
}

jQuery(document).ready(function(){
	var ct_auth_key = jQuery('.cleantalk_auth_key').prop('value'),
		ct_notice_cookie = ct_getCookie('ct_notice_cookie');

	//notice exclusions - know more
	let excl_fields_more_link = document.createElement('a');
	excl_fields_more_link.href = "https://cleantalk.org/help/exclusion-from-anti-spam-checking#joomla";
	excl_fields_more_link.target = "_blank";
	excl_fields_more_link.text = ct_exclusions_know_more;

	let excl_fields_question_span = document.createElement('span');
	excl_fields_question_span.className = "icon-question-sign";

	let exclusions_link_to_more_span = document.createElement('span');
	exclusions_link_to_more_span.appendChild(excl_fields_question_span)
	exclusions_link_to_more_span.appendChild(excl_fields_more_link)

	jQuery('#attrib-exclusions')[0].appendChild(exclusions_link_to_more_span);

	//notice about exclusion rules attach
	let excl_fields_p_notice = document.createElement('span');
	excl_fields_p_notice.innerText = ct_exclusions_common_notice;
	excl_fields_p_notice.style = "padding-left: 10px;";

	jQuery('#jform_params_fields_exclusions')[0].parentElement.appendChild(excl_fields_p_notice)

	// misc notices
	jQuery('#attrib-checkcomments,#options-checkcomments').append("<center><button id=\"check_spam_comments\" class=\"btn btn-success\" type=\"button\"><span class=\"icon-archive\"></span>"+ct_spamcheck_checkscomments+"</button><br /><br />"+ct_spamcheck_notice+"<br/><br/><input type='checkbox' name ='ct_impspamcheck_checkbox' value='0'>"+ct_impspamcheck_label+"</center><br/><br/>")
	jQuery('#attrib-connectionreports,#options-connectionreports').append("<div id='connection_reports'></div>");
	jQuery('<br/><h3>'+ct_form_settings_title+'</h3><label id="jform_params_hr_spacer-lbl" class=""><hr></label>')
		.insertBefore(jQuery('#jform_params_apikey').closest('.control-group').next().next());
	jQuery('#attrib-checkcomments,#options-checkcomments').append("<center><div id ='spam_results'></div>");
	jQuery('#attrib-checkcomments,#options-checkcomments,#attrib-connectionreports,#options-connectionreports').append("<img class='display_none' id='ct_preloader_spam_results' src='../plugins/system/cleantalkantispam/img/preloader.gif' />");
	//dev
	jQuery('#attrib-dev, #options-dev').append("<button class='btn btn-info' id='dev_btn_insert_spam_users' type='button'>insert 30 spam users</button><br/><br/>")

	if (['lc', 'loc', 'lh', 'test'].includes(window.location.host.match(/\.(.*)$/)[1])) {
		ct_serve_buttons();
	}

	// Viewing button to access CP
	if(ct_key_is_ok == 1){

		if(ct_service_id)
		{
			jQuery('#jform_params_apikey').css('border-bottom', '2px solid green')
				.parent()
				.append("<br/><b style='font-size:10px;'>"+ct_account_name_label+" "+ct_account_name_ob+"</b>");

			jQuery('.cleantalk_key_control')
				.parent().parent()
				.html('')
				.append("<div id='key_buttons_wrapper'></div>").children()
				.append("<a target='_blank'></a>").children('a')
				.attr('href', 'https://cleantalk.org/my/stat?service_id='+ct_service_id+'&user_token='+ct_user_token)
				.append("<button class='btn btn-success' id='ct_cp_button' type='button'><span class='icon-bars'></span>"+ct_statlink_label+"</button>")
				.append("<a target='_blank'></a>").children('a')
				.attr('href', 'https://cleantalk.org/my/support/open')
				.append("<button class='btn btn-info' id='ct_support_button' type='button'><span class='icon-question-sign'></span>"+ct_supportbtn_label+"</button>");

			jQuery('#key_buttons_wrapper').closest('.control-label').css('width', 'auto').next().empty();
		}
		// Viewing buttons to get key
	}else{
		if(ct_moderate_ip == 0){
			jQuery('#jform_params_apikey').css('border-bottom', '2px solid red')
				.parent()
				.append("<p class='ct_status_label red'>"+ct_key_is_bad_notice+"</p>");

			jQuery('.cleantalk_key_control')
				.parent().parent()
				.html('')
				.append("<div id='key_buttons_wrapper'></div>").children()
				.append("<button class='btn btn-success' id='ct_auto_button' type='button'>"+ct_autokey_label+"</button>")
				.append("<img class='display_none' id='ct_preloader' src='../plugins/system/cleantalkantispam/img/preloader.gif' />")
				.append("<a target='_blank'></a>").children('a')
				.attr('href', 'https://cleantalk.org/register?platform=joomla3&email=' + cleantalk_mail + '&website=' + cleantalk_domain)
				.append("<button class='btn btn-success' id='ct_manual_button' type='button'>"+ct_manualkey_label+"</button>")
				.append("<a target='_blank'></a>").children('a')
				.attr('href', 'https://cleantalk.org/my/support/open')
				.append("<button class='btn btn-info' id='ct_support_button' type='button'><span class='icon-question-sign'></span>"+ct_supportbtn_label+"</button>").parents('#key_buttons_wrapper')

				.append("<br><br>")
				.append("<p id='ct_email_warning'>"+ct_key_notice1+cleantalk_mail+ct_key_notice2+"</p>")
				.append("<br><br>")
				.append("<a id='ct_license_agreement' href='https://cleantalk.org/publicoffer' target='_blank'>"+ct_license_notice+"</a>");

			jQuery('#key_buttons_wrapper').closest('.control-label').css('width', 'auto').next().empty();

		}
	}
	if (ct_connection_reports_negative > 0 && ct_connection_reports_negative_report)
	{
		var html = ctRenderBlock('connection_reports_table_open', {});
		var negative_report = JSON.parse(ct_connection_reports_negative_report);
		if (negative_report) {
			negative_report.forEach(function(item, i, arr){
				var date = null;
				if (typeof item.date === "number") {
					date = new Date(item.date * 1000);
					date = date.toISOString().replace('T', ' ').substring(0, 19);
				}
				html += ctRenderBlock('connection_report_row', {
					date: date || 'Unknown date',
					page_url: item.page_url,
					lib_report: item.lib_report
				});
			});
			html += ctRenderBlock('connection_reports_table_close', {});
			html += ctRenderBlock('connection_report_send_button', {});
			jQuery('#connection_reports').append(html);
		}

	}
	else
		jQuery("#connection_reports").append("<center><h2>"+ct_connection_reports_no_reports+"</h2></center>")
	// Appereance fix

	jQuery('#key_buttons_wrapper').parents('.control-group').css('margin-bottom', 0);
	jQuery('#ct_preloader').css('margin', '-7px 8px 0 0');

	// Unknown
	if(ct_show_feedback && ct_notice_cookie == undefined && !ct_notice_review_done)
		jQuery('#system-message-container').prepend('<div class="alert alert-notice" style="text-align:center;padding-right:10px;" id="feedback_notice"><a href="#" style="font-size:15px;float:right;text-decoration:none;" id="feedback_notice_close">X</a><p style="margin-top:8px;">'+ct_show_feedback_mes+'</p></div>');


	// Notice for moderate IP
	if(ct_moderate_ip == 1)
		jQuery('#jform_params_apikey').parent().parent().append("<br /><h4>The anti-spam service is paid by your hosting provider. License #"+ct_ip_license+"</h4>");

	// Handler for review banner
	jQuery('#ct_review_link').click(function(){
		var data = {
			'ct_delete_notice': 'yes'
		};
		ct_setCookie('ct_notice_cookie', '1');
		ctAdminRequest(data, function () {
			close_animate = false;
			jQuery('#feedback_notice').hide();
		});
	});

	// Handler for closing banner
	jQuery('#feedback_notice_close').click(function(){
		animate_banner(0);
		ct_setCookie('ct_notice_cookie', '1');
		setTimeout(function(){
				close_animate = false;
				jQuery('#feedback_notice_close').parent().hide();
			},
			500);
	});

	// Handler for get_auto_key button
	jQuery('#ct_auto_button').click(function(){

		var data = {
			'get_auto_key': 'yes'
		};
		jQuery('#ct_preloader').show();
		ctAdminRequest(data, function (msg) {
			msg = jQuery.parseJSON(msg);
			if (msg.error_message) {
				var $errorAlert = jQuery('<div class="alert alert-error"><h4 class="alert-heading">Error</h4><p></p></div>');
				$errorAlert.prepend(jQuery('<button type="button" class="close" data-dismiss="alert">×</button>'));
				$errorAlert.find('p').text(msg.error_message);
				if (Object.prototype.hasOwnProperty.call(msg, 'account_exists') && Number(msg.account_exists) === 0) {
					$errorAlert.find('p').append('<br />').append(document.createTextNode(ct_register_error));
				}
				jQuery('#system-message-container').prepend($errorAlert);

				jQuery('#ct_preloader').hide();

			} else if (msg.auth_key) {

				jQuery('.cleantalk_auth_key').val(msg.auth_key);
				jQuery('#jform_params_user_token').val(msg.user_token);

				var $successAlert = jQuery('<div class="alert alert-success"><h4 class="alert-heading">Success!</h4><p></p></div>');
				$successAlert.prepend(jQuery('<button type="button" class="close" data-dismiss="alert">×</button>'));
				$successAlert.find('p').text(ct_register_message);
				jQuery('#system-message-container').prepend($successAlert);

				setTimeout(function () {
					jQuery('#ct_preloader').hide();
					Joomla.submitbutton('plugin.apply');
				}, 3000);
			}
		});
	});

	jQuery('#check_spam_comments').click(function(){
		off = 0;
		list_spam_results('comments',off,on_page);
	});

	jQuery('#send_connection_report').click(function(){
		var data = {
			'send_connection_report': 'yes'
		};
		jQuery("#connection_reports").empty();
		jQuery('#ct_preloader_spam_results').show();
		ctAdminRequest(data, function (msg) {
			msg = jQuery.parseJSON(msg);
			ctAppendPlainMessage('#connection_reports', msg.data);
			jQuery('#ct_preloader_spam_results').hide();
			setTimeout(function () { location.reload(); }, 2000);
		});
	});

	jQuery('#dev_btn_insert_spam_users').click(function(){
		var data ={
			'dev_insert_spam_users':'yes'
		};
		ctAdminRequest(data, function (msg) {
			msg = jQuery.parseJSON(msg);
			alert(msg.result);
		});

	});

	/**
	 * Users/Comments checker
	 * @since 3.3.0
	 */
	setTimeout(() => {
		const joomlaVersion = () => {
			if (typeof ct_joomla_version !== 'undefined') {
				return ct_joomla_version.substring(0, 1);
			}
		}

		if (joomlaVersion() === '4' || joomlaVersion() === '5') {
			const apbctSettingsTabs = jQuery('#myTab button[role="tab"]');
			jQuery.each(apbctSettingsTabs, function (index, tab) {
				let tabElement = jQuery(tab);
				if ( tabElement.attr('aria-expanded') ) {
					if (  tabElement.attr('aria-controls') === 'attrib-checkusers' ) {
						apbct.usersChecker.init();
					}
					if ( tabElement.attr('aria-controls') === 'attrib-checkcomments' ) {
						// @ToDo not implemented yet
						//apbct.commentsChecker.init();
					}
				}
			});
		} else {
			// Load init() to the active tab
			const apbctSettingsTabsContent = jQuery("#myTabContent>div");
			jQuery.each(apbctSettingsTabsContent, function (index, tab) {
				if ( tab.className.includes('active') && tab.id !== 'undefined' ) {
					if (  tab.id === 'attrib-checkusers' ) {
						apbct.usersChecker.init();
					}
					if ( tab.id === 'attrib-checkcomments' ) {
						// @ToDo not implemented yet
						//apbct.commentsChecker.init();
					}
				}
			});
		}

		// Set click listeners to the settings tabs
		const apbctSettingsTabs = jQuery("a[data-toggle='tab'], #myTab button");
		apbctSettingsTabs.on('click', function (e) {
			const clickedLink = e.target;
			if ( clickedLink.parentElement.className !== 'active' && clickedLink.hash !== 'undefined' ) {
				if ( clickedLink.hash === '#attrib-checkusers' || clickedLink.getAttribute("aria-controls") === 'attrib-checkusers' ) {
					apbct.usersChecker.init();
				}
				if ( clickedLink.hash === '#attrib-checkcomments' ) {
					// @ToDo not implemented yet
					//apbct.commentsChecker.init();
				}
			}
		});
	}, 110); // This delay is necessary because the Joomla tabs loaded in 100ms see media/system/js/tabs-state-uncompressed.js:242

	// Show Cookie setting description (for !Joomla 4+)
	jQuery('#jform_params_ct_set_cookies-desc').removeClass('d-none');

});

function delete_comment(all=false)
{
	var data = { 'ct_del_comment_ids[]' : []};
	if (all)
	{
		jQuery("input[type=checkbox]").each(function() {
			if (jQuery(this).attr('name').startsWith('ct_del_comment'))
			{
				var id=jQuery(this).attr('name').substring(jQuery(this).attr('name').lastIndexOf("[")+1,jQuery(this).attr('name').lastIndexOf("]"));
				data['ct_del_comment_ids[]'].push(id);
			}
		});
	}
	else
	{
		jQuery("input:checked").each(function() {
			if (jQuery(this).attr('name').startsWith('ct_del_comment'))
			{
				var id=jQuery(this).attr('name').substring(jQuery(this).attr('name').lastIndexOf("[")+1,jQuery(this).attr('name').lastIndexOf("]"));
				data['ct_del_comment_ids[]'].push(id);
			}
		});
	}
	if (data['ct_del_comment_ids[]'].length>0)
	{
		if (confirm(ct_spamcheck_comments_delconfirm)==true)
		{
			jQuery("#spam_results").empty();
			jQuery('#ct_preloader_spam_results').show();
			ctAdminRequest(data, function (msg) {
				msg = jQuery.parseJSON(msg);
				ctAppendPlainMessage('#spam_results', msg.data);
				jQuery('#ct_preloader_spam_results').hide();
				setTimeout(function () { jQuery('#check_spam_comments').click(); }, 2000);
			});
		}

	}
	else alert(ct_spamcheck_comments_delconfirm_error);
}

function load_more()
{
	var get_table_type = document.getElementById('spamusers_table')?'users':document.getElementById('spamcomments_table')?'comments':'';
	if (get_table_type)
		list_spam_results(get_table_type,off,on_page);
}

function list_spam_results(type,offset,amount)
{
	var data = {
		'check_type': type,
		'offset':offset,
		'amount':amount,
		'improved_check':jQuery("#ct_impspamcheck_checkbox").is(":checked")
	};
	if (off==0)
		jQuery("#spam_results").empty();
	jQuery('#ct_preloader_spam_results').show();
	ctAdminRequest(data, function (msg) {
		msg = jQuery.parseJSON(msg);
		if (msg.result == 'success') {
			var spam_content = (msg.data.spam_users) ? msg.data.spam_users : msg.data.spam_comments;
			if (spam_content.length > 0) {
				if (off == 0) {
					if (type == 'comments') {
						var html = ctRenderBlock('spam_comments_toolbar', {});
						html += ctRenderBlock('spam_comments_table_open', {});
						spam_content.forEach(function (item) {
							html += ctRenderBlock('spam_comment_row', item);
						});
						html += ctRenderBlock('spam_comments_table_close', {});
						if (spam_content.length >= on_page) {
							html += ctRenderBlock('spam_load_more', {});
						}
						jQuery('#spam_results').append(html);
					}
				} else {
					if (type == 'comments') {
						spam_content.forEach(function (item) {
							ctAppendBlock('#spamcomments_table tbody', 'spam_comment_row', item);
						});
					}
					jQuery('html, body').animate({ scrollTop: jQuery(document).height() }, 'slow');
				}
				off = spam_content[spam_content.length - 1]["id"];
			}
		}
		if (msg.result == 'error' && (!document.getElementById('spamusers_table') && !document.getElementById('spamcomments_table'))) {
			ctAppendPlainMessage('#spam_results', msg.data);
		}
		jQuery('#ct_preloader_spam_results').hide();
	});
}

function ct_serve_buttons() {
	jQuery('.cleantalk_auth_key')
		.closest('.control-group')
		.append("<div id='cleantalk_service_buttons_wrapper'></div>")
		.append("<input type='button' id='ct_serve_run_cron_sfw_send_logs' value='run cron task - send sfw logs in 120 sec'>")
		.append("&nbsp;")
		.append("<input type='button' id='ct_serve_run_cron_sfw_update' value='run cron task - sfw update in 120 sec'>");

	jQuery('#ct_serve_run_cron_sfw_send_logs').on('click', function() {
		var data = {
			'ct_serve_run_cron_sfw_send_logs': 'yes'
		};
		ctAdminRequest(data, function () {
			alert('OK');
		});
	});

	jQuery('#ct_serve_run_cron_sfw_update').on('click', function() {
		var data = {
			'ct_serve_run_cron_sfw_update': 'yes'
		};
		ctAdminRequest(data, function () {
			alert('OK');
		});
	});
}

