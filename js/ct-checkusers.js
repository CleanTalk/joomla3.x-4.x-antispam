
/* global jQuery, Joomla */

window.apbct = window.apbct || {};

(function( $, apbct ) {

    'use strict';

    let usersChecker = {
        totalUsers: 0,
        limit: 20,
        offset: 0,
        improvedCheck: false
    };

    apbct = apbct || {};

    apbct.usersChecker = usersChecker;

    const preloader = "<img id='ct_preloader_spam_results' src='../plugins/system/cleantalkantispam/img/preloader.gif'  alt='CleanTalk preloader' />";

    let tabIsLoaded = false;

    let scanInProgress = false;

    usersChecker.init = () => {

        if ( tabIsLoaded ) {
            return;
        }

        usersChecker.enablePreloader();

        usersChecker.getTabContent().then(
            content => {
                usersChecker.layoutDraw(content);
                usersChecker.setListeners();
                tabIsLoaded = true;
            },
            error  => {
                usersChecker.layoutDraw(error.response);
            }
        );

    };

    usersChecker.setListeners = () => {
        $('#check_spam_users').click(() => {
            usersChecker.improvedCheck = $("#ct_impspamcheck_checkbox").is(":checked");

            usersChecker.clearUserCheckerResults()
                .then((response) => {
                    try {
                        // Clear Frontend Results
                        const responseObject = JSON.parse(response);
                        jQuery('#ct_checking_count span').html(responseObject.users_count);
                        jQuery('#ct_userchecking__checking_date').html(responseObject.current_date);
                        usersChecker.reactUserCheckingFrontendData();

                        return usersChecker.runUserChecker(usersChecker.limit, usersChecker.offset);
                    } catch (error) {
                        usersChecker.runUserCheckerError(error);
                    }
                })
                .then(
                    response => {
                        try {
                            usersChecker.runUserCheckerSuccess(JSON.parse(response));
                        } catch (error) {
                            usersChecker.runUserCheckerError(error);
                        }
                    },
                    error  => {
                        usersChecker.runUserCheckerError(error.response);
                    }
                );
        });
        $('.cleantalk_pagination li').click((e) => {
            const target = $(e.target);
            if ( target.hasClass('disabled') || target.hasClass('active') ) {
                return;
            }

            target.addClass('disabled');

            let page = 1;
            if ( target.data('page_number') ) {
                page = target.data('page_number');
            } else if ( e.target.id === 'cleantalk_pagination_next' ) {
                page = $('.cleantalk_pagination li.active').data('page_number') + 1;
            } else if ( e.target.id === 'cleantalk_pagination_prev' ) {
                page = $('.cleantalk_pagination li.active').data('page_number') - 1;
            }

            usersChecker.loadScanResults(page).then(
                content => {
                    $('.cleantalk_pagination li').removeClass('active');
                    $('.cleantalk_pagination li[data-page_number="'+ page +'"]').addClass('active');
                    usersChecker.loadScanResultsSuccess(content);
                    usersChecker.setListeners();
                    target.removeClass('disabled');
                },
                error  => {
                    usersChecker.loadScanResultsError(error);
                    target.removeClass('disabled');
                }
            );
        });
        $('#delete_all_spam_users').click(() => usersChecker.deleteUsers(true));
        $('#delete_sel_spam_users').click(() => usersChecker.deleteUsers());
    };

    usersChecker.getTabContent = () => {
        const data = {action: 'usersChecker', route: 'getTabContent'};
        return usersChecker.ajaxRequest(data);
    };

    usersChecker.loadScanResults = (page) => {
        const data = {action: 'usersChecker', route: 'getScanResults', page: page};
        return usersChecker.ajaxRequest(data);
    };

    usersChecker.loadScanResultsSuccess = (content) => {
        usersChecker.layoutDrawById('ct_checking_results', content);
    };

    usersChecker.loadScanResultsError = (error) => {
        usersChecker.layoutDrawById('ct_checking_results', error);
    };

    usersChecker.clearUserCheckerResults = () => {
        usersChecker.layoutClearById('spamusers_table');
        const data = {action: 'usersChecker', route: 'clearResults'};
        return usersChecker.ajaxRequest(data);
    };

    usersChecker.runUserChecker = (limit, offset) => {
        if ( ! scanInProgress ) {
            scanInProgress = true;
            usersChecker.layoutAppend(preloader);
            usersChecker.blockButtons();
        }

        let data = {
            action: 'usersChecker',
            route: 'scan',
            limit: limit,
            offset: offset,
            improved_check: usersChecker.improvedCheck
        };
        return usersChecker.ajaxRequest(data);
    };

    usersChecker.runUserCheckerSuccess = (response) => {
        if (response.checkingCount !== undefined && response.foundedSpam !== undefined) {
            usersChecker.reactUserCheckingFrontendData(response.checkingCount, response.foundedSpam);
        }

        if ( response.end ) {
            usersChecker.disablePreloader();
            usersChecker.unblockButtons();
            usersChecker.loadScanResults(1).then(
                content => {
                    usersChecker.loadScanResultsSuccess(content);
                    usersChecker.setListeners();
                },
                error  => {
                    usersChecker.loadScanResultsError(error);
                }
            );
            scanInProgress = false;
        } else {
            // Continue checking
            usersChecker.runUserChecker(usersChecker.limit, response.offset).then(
                response => {
                    try {
                        usersChecker.runUserCheckerSuccess(JSON.parse(response));
                    } catch (error) {
                        usersChecker.runUserCheckerError(error);
                    }
                },
                error  => {
                    usersChecker.runUserCheckerError(error.response);
                }
            );
        }
    };

    usersChecker.runUserCheckerError = (error) => {
        usersChecker.disablePreloader();
        usersChecker.unblockButtons();
        usersChecker.layoutDrawById('ct_checking_results', 'AJAX error: ' . error);
        scanInProgress = false;
    };

    usersChecker.deleteUsers = (all) => {
        let data = {
            action: 'usersChecker',
            route: 'delete',
            ct_del_user_ids : []
        };
        if ( all ) {
            $("input[type=checkbox]").each(function() {
                if ( $(this).attr('name').startsWith('ct_del_user') ) {
                    let id = $(this).attr('name').substring($(this).attr('name').lastIndexOf("[") + 1, $(this).attr('name').lastIndexOf("]"));
                    data.ct_del_user_ids.push(id);
                }
            });
        } else {
            $("input:checked").each(function() {
                if ( $(this).attr('name').startsWith('ct_del_user') ) {
                    let id = $(this).attr('name').substring($(this).attr('name').lastIndexOf("[") + 1, $(this).attr('name').lastIndexOf("]"));
                    data.ct_del_user_ids.push(id);
                }
            });
        }
        if ( data.ct_del_user_ids.length > 0 ) {
            // @ToDo make this text translatable
            if ( window.confirm('Are you sure?')===true )
            {
                usersChecker.layoutAppend(preloader);
                usersChecker.ajaxRequest(data).then(
                    response => {
                        usersChecker.disablePreloader();
                        response = jQuery.parseJSON(response);
                        alert(response.data);
                        usersChecker.loadScanResults(1).then(
                            content => {
                                usersChecker.loadScanResultsSuccess(content);
                                usersChecker.setListeners();
                            },
                            error  => {
                                usersChecker.loadScanResultsError(error);
                            }
                        );
                    }
                );
            }

        } else  {
            // @ToDo make this text translatable
            alert('No users selected.');
        }
    };

    usersChecker.layoutDraw = (content) => {
        document.getElementById('attrib-checkusers').innerHTML = content;
    };

    usersChecker.layoutDrawById = (id, content) => {
        document.getElementById(id).innerHTML = content;
    };

    usersChecker.layoutAppend = (content) => {
        document.getElementById('attrib-checkusers').insertAdjacentHTML('beforeend', content);
    };

    usersChecker.layoutAppendById = (id, content) => {
        document.getElementById(id).insertAdjacentHTML('beforeend', content);
    };

    usersChecker.layoutClear = () => {
        document.getElementById('attrib-checkusers').innerHTML = '';
    };

    usersChecker.layoutClearById = (id) => {
        if ( document.getElementById(id) !== null ) {
            document.getElementById(id).remove();
        }
    };

    usersChecker.enablePreloader = () => {
        usersChecker.layoutAppend(preloader);
    };

    usersChecker.disablePreloader = () => {
        usersChecker.layoutClearById('ct_preloader_spam_results');
    };

    usersChecker.blockButtons = () => {
        $('#check_spam_users').attr('disabled', 'disabled');
    };

    usersChecker.unblockButtons = () => {
        $('#check_spam_users').removeAttr('disabled');
    };

    usersChecker.ajaxRequest = (data) => {
        return new Promise((resolve, reject) => {
            Joomla.request({
                url: 'index.php?option=com_ajax&plugin=cleantalkantispam&format=raw',
                method: 'POST',
                data: JSON.stringify(data),
                headers: {
                    'Cache-Control' : 'no-cache',
                    'Content-Type': 'application/json'
                },
                onSuccess: function (response){
                    resolve(response);
                },
                onError: function (error){
                    reject(error);
                }
            });
        });
    };

    usersChecker.reactUserCheckingFrontendData = (checkingCount = '0', foundedSpam = '0') => {
        jQuery('#ct_userchecking__checking_count').html(checkingCount);
        jQuery('#ct_userchecking__found_spam').html(foundedSpam);
    }

})( jQuery, window.apbct );
