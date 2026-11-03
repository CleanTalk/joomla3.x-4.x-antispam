Anti-spam plugin for Joomla 3.x-4.x-5.x-6.x
============
Version 3.4.0
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

## Static analysis

Psalm is a root Composer development dependency (`vimeo/psalm: ^4.8`, allowing
Psalm 4 releases from 4.8 up to, but not including, 5.0). The plugin is analyzed
with a PHP 7.2 target at error level 3. Composer resolves dependencies for PHP
7.2.0, and CI runs all three checks on PHP 7.2.

Run all checks from the repository root:

```sh
composer install --prefer-dist --no-interaction --no-progress
composer test
```

`composer test` runs PHPCS, PHPUnit and Psalm in that order, stopping on failure.
Use `composer test:psalm` to run only Psalm. Local checks can also run on PHP 8.2;
that does not replace the actual PHP 7.2 run in CI. Composer's platform setting
selects compatible dependencies, but does not install or switch the interpreter.
Psalm uses a full uncached analysis for reproducible baseline matching.

The analysis includes the root PHP files and all of `lib/`, including
`Cleantalk/Common` and `Cleantalk/Custom`. Tests, tooling, `vendor/` and
`node_modules/` are excluded. `lib/Cleantalk/Common/Templates/Singleton.php` is
also excluded from direct analysis because Psalm 4.30.0 crashes on its
conditional trait declaration; its definitions remain available to dependent
classes. The rest of `Common` remains in scope.
Composer's CleanTalk installer can replace the
tracked libraries under `lib/`. To install development dependencies without
running installer plugins or Composer scripts, use
`composer install --no-plugins --no-scripts --prefer-dist --no-interaction --no-progress`.
CI restores the checked-out `lib/` before running the checks.

### Joomla API stubs

`tests/psalm/stubs/` describes the API used by this plugin, based on the official
[Joomla 6.2.0 stable full package](https://github.com/joomla/joomla-cms/releases/tag/6.2.0).
The CMS does not need to be installed or executed to run Psalm.

| Stub file | Source in the Joomla 6.2.0 full package |
|---|---|
| `joomla-6.phpstub` | `libraries/src/`: Factory, Plugin, Application, Document, Language, Session, Uri, User, Table, HTML and Mail |
| `framework.phpstub` | `libraries/vendor/joomla/`: Registry, Input and Database; the Event dispatcher type accepted by the plugin constructor |
| `aliases.phpstub` | `libraries/loader.php` and the aliases registered by this plugin in `cleantalkantispam.php` / `updater.php` |

Inherited methods and trait members are represented on the used classes. SQL
query return types and table fields are derived from implementations and the CMS
database schema. `Factory::getApplication()` is modeled as `CMSApplication` for
the plugin's site/administrator web context; Joomla's general factory contract
also allows other application implementations. Input magic properties are
restricted to the documented names, not an arbitrary-property fallback.

The `.phpstub` files are loaded only by Psalm, never by the plugin or PHPUnit.
Their classes are preloaded before project scanning so Psalm 4 can resolve
Joomla parent classes and analyze the plugin's method bodies.
They cover the API currently used by the plugin, not the entire CMS. When a new
Joomla API is used, check its declaration, inherited members and possible failure
returns in the pinned CMS sources before extending the stubs.

Joomla 3-5 stubs are a separate future step. The Joomla 6 analysis also sees
legacy branches in the plugin; missing legacy APIs (for example `isAdmin()`,
`isSite()` and database `query()`) are not invented in the stubs.
Optional aliases such as `JFilterInput` and `JInstaller` require the CMS
`behaviour/compat6` plugin with `classes_aliases` enabled; this analysis does not
assume that optional configuration. The stubs provide only the aliases
explicitly registered by the CleanTalk plugin.
Third-party extension APIs are not part of the Joomla stubs. These existing
findings remain visible in the baseline. This analysis does not prove runtime
compatibility with every supported Joomla version, and Joomla 6 itself cannot
run on PHP 7.2.

### Baseline maintenance

`psalm-baseline.xml` records existing findings. A normal run uses it and should
exit successfully; new errors must fail the common CI test job. The CI job
never regenerates the baseline.

After fixing existing findings, remove obsolete baseline entries with:

```sh
php vendor/bin/psalm --config=psalm.xml --update-baseline --no-cache --no-progress
composer test:psalm
```

Only when deliberately accepting a new snapshot of existing findings, regenerate
the baseline and review its diff:

```sh
php vendor/bin/psalm --config=psalm.xml --set-baseline=psalm-baseline.xml --no-cache --no-progress
composer test:psalm
```

Do not regenerate the baseline just to make a pull request pass. Psalm does not
replace the existing PHPCompatibility and PHPUnit checks.

### Websites that trust CleanTalk!

![CleanTalk Anti-Spam Rating](https://cleantalk.org/webpack/img/cleantalk_rating.png)
