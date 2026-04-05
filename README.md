Anti-spam plugin for Joomla 3.X.-4.x-5.x-6.x
============
Version 3.2.5
=======

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

If you find this project useful, please consider starring ⭐ it on GitHub — it helps us grow and support development!

## Requirements

* CleanTalk account https://cleantalk.org/register?product=anti-spam

### Websites that trust CleanTalk!

![CleanTalk Anti-Spam Rating](https://cleantalk.org/webpack/img/cleantalk_rating.png)
