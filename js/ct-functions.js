apbctLocalStorage = {
		get : function(key, property) {
			if ( typeof property === 'undefined' ) {
				property = 'value';
			}
			const storageValue = localStorage.getItem(key);
			if ( storageValue !== null ) {
				try {
					const json = JSON.parse(storageValue);
					return json.hasOwnProperty(property) ? JSON.parse(json[property]) : json;
				} catch (e) {
					return storageValue;
				}
			}
			return false;
		},
		set : function(key, value, is_json = true) {
			if (is_json){
				let objToSave = {'value': JSON.stringify(value), 'timestamp': Math.floor(new Date().getTime() / 1000)};
				localStorage.setItem(key, JSON.stringify(objToSave));
			} else {
				localStorage.setItem(key, value);
			}
		},
		isAlive : function(key, maxLifetime) {
			if ( typeof maxLifetime === 'undefined' ) {
				maxLifetime = 86400;
			}
			const keyTimestamp = this.get(key, 'timestamp');
			return keyTimestamp + maxLifetime > Math.floor(new Date().getTime() / 1000);
		},
		isSet : function(key) {
			return localStorage.getItem(key) !== null;
		},
		delete : function (key) {
			localStorage.removeItem(key);
		},
		getCleanTalkData : function () {
			let data = {}
			for(let i=0; i<localStorage.length; i++) {
				let key = localStorage.key(i);
				if (key.indexOf('ct_') !==-1 || key.indexOf('apbct_') !==-1){
					data[key.toString()] = apbctLocalStorage.get(key)
				}
			}
			return data
		},

	}

function ctSetCookie(c_name, value) {
	if (typeof ct_setcookie !== "undefined" && ct_setcookie) {
		document.cookie = c_name + "=" + encodeURIComponent(value) + "; path=/";
	}	
}

ct_attach_event_handler(window, "DOMContentLoaded", ct_ready);

//Stop observing function
function ctMouseStopData(){
	if(typeof window.addEventListener == "function")
		window.removeEventListener("mousemove", ctFunctionMouseMove);
	else
		window.detachEvent("onmousemove", ctFunctionMouseMove);
	clearInterval(ctMouseReadInterval);
	clearInterval(ctMouseWriteDataInterval);				
}

//Stop key listening function
function ctKeyStopStopListening(){
	if(typeof window.addEventListener == "function"){
		window.removeEventListener("mousedown", ctFunctionFirstKey);
		window.removeEventListener("keydown", ctFunctionFirstKey);
	}else{
		window.detachEvent("mousedown", ctFunctionFirstKey);
		window.detachEvent("keydown", ctFunctionFirstKey);
	}			
}

var d = new Date(), 
	ctTimeMs = new Date().getTime(),
	ctMouseEventTimerFlag = true, //Reading interval flag
	ctMouseData = "[",
	ctMouseDataCounter = 0;
	
//Reading interval
var ctMouseReadInterval = setInterval(function(){
		ctMouseEventTimerFlag = true;
	}, 150);
	
//Writting interval
var ctMouseWriteDataInterval = setInterval(function(){ 
		var ctMouseDataToSend = ctMouseData.slice(0,-1).concat("]");
		ctSetCookie("ct_pointer_data", ctMouseDataToSend);
	}, 1200);

//Logging mouse position each 300 ms
var ctFunctionMouseMove = function output(event){
	if(ctMouseEventTimerFlag == true){
		var mouseDate = new Date();
		ctMouseData += "[" + event.pageY + "," + event.pageX + "," + (mouseDate.getTime() - ctTimeMs) + "],";
		ctMouseDataCounter++;
		ctMouseEventTimerFlag = false;
		if(ctMouseDataCounter >= 100)
			ctMouseStopData();
	}
}
//Writing first key press timestamp
var ctFunctionFirstKey = function output(event){
	var KeyTimestamp = Math.floor(new Date().getTime()/1000);
	ctSetCookie("ct_fkp_timestamp", KeyTimestamp);
	ctKeyStopStopListening();
}

if(typeof window.addEventListener == "function"){
	window.addEventListener("mousemove", ctFunctionMouseMove);
	window.addEventListener("mousedown", ctFunctionFirstKey);
	window.addEventListener("keydown", ctFunctionFirstKey);
}else{
	window.attachEvent("onmousemove", ctFunctionMouseMove);
	window.attachEvent("mousedown", ctFunctionFirstKey);
	window.attachEvent("keydown", ctFunctionFirstKey);
}
// Ready function
function ct_ready(){
	ctSetCookie("ct_ps_timestamp", Math.floor(new Date().getTime()/1000));
	ctSetCookie("ct_fkp_timestamp", "0");
	ctSetCookie("ct_pointer_data", "0");
	ctSetCookie("ct_timezone", new Date().getTimezoneOffset()/60*(-1));
	ctSetCookie("ct_visible_fields", 0);
	ctSetCookie("ct_visible_fields_count", 0);
	setTimeout(function(){
		for(var i = 0; i < document.forms.length; i++){
			var form = document.forms[i];

			if (!form.name && !form.id) {
				continue;
			}

			form.addEventListener('submit', function () {
				// Get only fields
				var elements = [];
				for(var key in this.elements){
					if(!isNaN(+key))
						elements[key] = this.elements[key];
				}

				// Filter fields
				elements = elements.filter(function(elem){

					var pass = true;

					// Filter fields
					if( getComputedStyle(elem).display    === "none" ||   // hidden
						getComputedStyle(elem).visibility === "hidden" || // hidden
						getComputedStyle(elem).opacity    === "0" ||      // hidden
						elem.getAttribute("type")         === "hidden" || // type == hidden
						elem.getAttribute("type")         === "submit" || // type == submit
						elem.value                        === ""       || // empty value
						elem.getAttribute('name')         === null
					){
						return false;
					}

					// Filter elements with same names for type == radio
					if(elem.getAttribute("type") === "radio"){
						elements.forEach(function(el, j, els){
							if(elem.getAttribute('name') === el.getAttribute('name')){
								pass = false;
								return;
							}
						});
					}

					return true;
				});

				// Visible fields count
				var visible_fields_count = elements.length;

				// Visible fields
				var visible_fields = '';
				elements.forEach(function(elem, i, elements){
					visible_fields += " " + elem.getAttribute("name");
				});
				visible_fields = visible_fields.trim();

				ctSetCookie("ct_visible_fields", visible_fields);
				ctSetCookie("ct_visible_fields_count", visible_fields_count);
			});
		}
	}, 1000);
}

function ct_attach_event_handler(elem, event, callback){
	if(typeof window.addEventListener === "function") elem.addEventListener(event, callback);
	else                                              elem.attachEvent(event, callback);
}

function ct_remove_event_handler(elem, event, callback){
	if(typeof window.removeEventListener === "function") elem.removeEventListener(event, callback);
	else                                                 elem.detachEvent(event, callback);
}

function ct_attach_event_token(){
	if (typeof apbctLocalStorage !== "undefined"){
		const ct_event_token_string = apbctLocalStorage.get('bot_detector_event_token')
		const ct_event_token_obj = JSON.parse(ct_event_token_string.toString())
		if (typeof ctSetCookie == "function" && typeof ct_event_token_obj.value != "undefined"){
			const value = ct_event_token_obj.value;
			if (typeof value === "string" && value.length === 64){
				ctSetCookie("ct_event_token", ct_event_token_obj.value);
				return true;
			}
		}
	}
	return false;
}
