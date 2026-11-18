Anti-spam plugin for Joomla 3.x-4.x-5.x-6.x
============
Version 3.4.1
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

* PHP 7.2 or newer
* CleanTalk account https://cleantalk.org/register?product=anti-spam

## Code style and PHP compatibility

Run `composer test:phpcs` from the repository root to use `tests/.phpcs.xml`.
The ruleset checks PHP 7.2 and newer compatibility and PSR-12 coding style,
with warnings and `PSR12.ControlStructures.ControlStructureSpacing` disabled.
`lib/Cleantalk/Common/` is excluded only from PSR-12; PHPCompatibility
continues to check it.
Existing non-camelCase method names are preserved with per-method
`phpcs:ignore` annotations; the leading underscore in
`_cleantalk_user_has_role_id()` is also explicitly exempted.
Naming rules remain enabled for new methods.
The legacy Joomla plugin and installer entry-point classes are explicitly
exempted from namespace and PascalCase requirements, preserving their global
names.

### Websites that trust CleanTalk!

![CleanTalk Anti-Spam Rating](https://cleantalk.org/webpack/img/cleantalk_rating.png)
