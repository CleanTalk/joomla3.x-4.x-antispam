<?php
// Check to ensure this file is included in Joomla!
use Joomla\CMS\Access\Access;
use Joomla\CMS\Helper\UserGroupsHelper;

defined('_JEXEC') or die('Restricted access');

jimport('joomla.form.formfield');

class JFormFieldClUserGroupList extends JFormField {

    protected $type = 'clusergrouplist';

    // getLabel() left out

    public function getInput() {

        $out_html = '<select multiple id="' . $this->name . '" name="' . $this->name . '" class="form-select valid form-control-success" aria-describedby="' . $this->name . '" aria-invalid="false">';
        foreach ($this->getOptions()[0] as $option) {

            $selected = '';
            if(in_array($option->value, $this->value)) {
                $selected = 'selected';
            }

            $out_html .= '<option ' . $selected . ' value="' . $option->value . '">' . $option->text . '</option>';
        }
        $out_html .= '</select>';

        return $out_html;
    }

    /**
     * Method to get the options to populate list
     *
     * @return  array  The field option objects.
     *
     * @since   1.7
     */
    public function getOptions()
    {
        $checkSuperUser = (int) $this->getAttribute('checksuperusergroup', 0);

        // Cache user groups base on checksuperusergroup attribute value
        if (true)
        {
            $groups       = UserGroupsHelper::getInstance()->getAll();
            $cacheOptions = array();

            foreach ($groups as $group)
            {
                // Don't list super user groups.
                if ($checkSuperUser && Access::checkGroup($group->id, 'core.admin'))
                {
                    continue;
                }

                $cacheOptions[] = (object) array(
                    'text'  => str_repeat('- ', $group->level) . $group->title,
                    'value' => $group->id,
                    'level' => $group->level,
                );
            }

            $options[$checkSuperUser] = $cacheOptions;
        }

        return $options;
    }
}
