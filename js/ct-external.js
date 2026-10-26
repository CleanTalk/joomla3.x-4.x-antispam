function ct_check_external(){

    for(var i = 0, host = '', action = ''; i < document.forms.length; i++){
        var form = document.forms[i];

        if( typeof(form.action) == 'string' ) {

            //skip excluded forms
            if ( formIsExclusion(form)) {
                return;
            }

            action = document.forms[i].action;
            if( action.indexOf('http://') != -1 || action.indexOf('https://') != -1 ){

                tmp  = action.split('//');
                tmp  = tmp[1].split('/');
                host = tmp[0].toLowerCase();

                if( host != location.hostname.toLowerCase()){
                    var ct_action = document.createElement("input");
                    ct_action.name='ct_action';
                    ct_action.value=action;
                    ct_action.type='hidden';
                    document.forms[i].appendChild(ct_action);

                    var ct_method = document.createElement("input");
                    ct_method.name='ct_method';
                    ct_method.value=document.forms[i].method;
                    ct_method.type='hidden';
                    document.forms[i].appendChild(ct_method);

                    document.forms[i].method = 'POST';

                    if (!window.location.origin){
                        window.location.origin = window.location.protocol + "//" + window.location.hostname;
                    }
                    document.forms[i].action = window.location.origin;
                }
            }
        }
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const nativeSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function (...args) {
        if ( ! apbctIsHubSpotForm(this) ) {
            return Reflect.apply(nativeSubmit, this, args);
        }
        let data = {};
        let elems = this.elements;
        const originalFormObject = this;
        const originalFormArgs = args;
        elems = Array.prototype.slice.call(elems);

        elems.forEach(
            function ( elem, y ) {
                if(elem.name === '' ) {
                    data['input_' + y] = elem.value;
                } else {
                    data[elem.name] = elem.value;
                }
            }
        );
        Joomla.request({
            url: 'index.php?option=com_ajax&plugin=cleantalkantispam&format=json',
            method: 'POST',
            data: JSON.stringify({
                'action' : 'cleantalk_force_ajax_check',
                'form_data': data
            }),
            headers: {
                'Cache-Control' : 'no-cache'
            },
            onSuccess: function (response, xhr){
                try {
                    let responseData = JSON.parse(response);
                    responseData = responseData.data[0];
                    if ( responseData.allow !== 0 ) {
                        return Reflect.apply(nativeSubmit, originalFormObject, originalFormArgs);
                    } else {
                        alert(result.ct_result_comment);
                    }
                } catch (e) {
                    console.log(e.toString());
                    console.log(e.fileName);
                    console.log(e.lineNumber);
                    return Reflect.apply(nativeSubmit, originalFormObject, originalFormArgs);
                }
            }
        });
    };
    setTimeout(function () {
        ct_check_external();
    }, 1500);
});

function formIsExclusion(currentForm)
{
    let exclusions_by_id = [
    ]

    let exclusions_by_role = [
    ]

    let exclusions_by_class = [
    ]

    let result = false

    try {
        action = currentForm.action;
        if (action.indexOf('cloudbeds.com') != -1) {
            result = true;
        }

        exclusions_by_id.forEach(function (exclusion_id) {
            const form_id = currentForm.getAttribute('id')
            if ( form_id !== null && typeof (form_id) !== 'undefined' && form_id.indexOf(exclusion_id) !== -1 ) {
                result = true
            }
        })

        exclusions_by_class.forEach(function (exclusion_class) {
            const form_class = currentForm.getAttribute('class')
            if ( form_class !== null && typeof form_class !== 'undefined' && form_class.indexOf(exclusion_class) !== -1 ) {
                result = true
            }
        })

        exclusions_by_role.forEach(function (exclusion_role) {
            const form_role = currentForm.getAttribute('id')
            if ( form_role !== null && typeof form_role !== 'undefined'&& form_role.indexOf(exclusion_role) !== -1 ) {
                result = true
            }
        })
    } catch (e) {
        console.table('APBCT ERROR: formIsExclusion() - ',e)
    }

    if ( apbctIsHubSpotForm(currentForm) ) {
        result = true
    }

    return result
}

/**
 * Complex check for HubSpot forms.
 *
 * @param form
 * @return {boolean}
 */
function apbctIsHubSpotForm(form) {
    if (!(form instanceof HTMLFormElement)) return false;

    return (
        form.matches('form[data-hsfc-id="Form"]') &&
        form.matches('form.hsfc-Form') &&
        form.matches('form[data-form-id]')
    );
}
