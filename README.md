Anti-spam plugin for Joomla 3.X.-4.x
============

<<<<<<< HEAD
Version 1.8.2
=======
Version 1.8.1
>>>>>>> origin/output_errors_related_to_curl_allow_url_fopen

## Simple antispam test

Example how to use plugin to filter spam bots at any Joomla form.


            $result = plgSystemCleantalkantispam::onSpamCheck(
                '',
                array(
                    'sender_email' => $contact_email, 
                    'sender_nickname' => $contact_nickname, 
                    'message' => $contact_message
                ));

            if ($result !== true) {
                JFactory::getApplication()->enqueueMessage($this->_subject->getError(),'error');
            }
