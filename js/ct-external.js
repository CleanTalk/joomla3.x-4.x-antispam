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

    return result
}