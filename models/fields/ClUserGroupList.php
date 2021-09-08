<?php
defined('_JEXEC') or die('Restricted access');

jimport('joomla.form.formfield');
JLoader::register('UsersHelper', JPATH_ADMINISTRATOR.DIRECTORY_SEPARATOR.'components'.DIRECTORY_SEPARATOR.'com_users'.DIRECTORY_SEPARATOR.'helpers'.DIRECTORY_SEPARATOR.'/users.php');

class JFormFieldClUserGroupList extends JFormField {

    protected $type = 'clusergrouplist';

    // getLabel() left out

    public function getInput() {

        $out_html = '<select multiple id="' . $this->id . '" name="' . $this->name . '" class="form-select valid form-control-success" aria-describedby="' . $this->name . '" aria-invalid="false">';
        foreach ($this->getOptions() as $option) {

            $selected = '';
            if(is_array($this->value) && in_array($option->value, $this->value)) {
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
        return UsersHelper::getGroups();
    }
}
