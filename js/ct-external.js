function ct_check_internal(){
    
        for(var i = 0, host = '', action = ''; i < document.forms.length; i++){
            var form = document.forms[i];
            
            if( typeof(form.action) == 'string' ){
            
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
            
            form.onsubmit_prev = form.onsubmit;
            form.onsubmit = function(event){
                if(this.onsubmit_prev instanceof Function){
                    this.onsubmit_prev.call(this, event);
                }
            }
        }      
}
    
jQuery(document).ready( function(){
    ct_check_internal();
});