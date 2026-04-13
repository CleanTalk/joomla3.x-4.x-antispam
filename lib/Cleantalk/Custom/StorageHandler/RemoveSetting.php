<?php

namespace Cleantalk\Custom\StorageHandler;

/**
 * Implementation of the remove function for the JRegistry class in case it is missing there
 */
class RemoveSetting extends \JRegistry
{
    /**
     * Delete a registry value
     *
     * @param  string  $path  Registry Path (e.g. joomla.content.showauthor)
     *
     * @return  mixed  The value of the removed node or null if not set
     */
    public function remove($path)
    {
        // Cheap optimisation to direct remove the node if there is no separator
        if ($this->separator === null || $this->separator === '' || !\strpos($path, $this->separator)) {
            $result = (isset($this->data->$path) && $this->data->$path !== null && $this->data->$path !== '')
                ? $this->data->$path
                : null;


            unset($this->data->$path);

            return $result;
        }

        /*
         * Explode the registry path into an array and remove empty
         * nodes that occur as a result of a double separator. ex: joomla..test
         * Finally, re-key the array so they are sequential.
         */
        $nodes = \array_values(\array_filter(\explode($this->separator, $path), 'strlen'));

        if (!$nodes) {
            return null;
        }

        // Initialize the current node to be the registry root.
        $node   = $this->data;
        $parent = null;

        // Traverse the registry to find the correct node for the result.
        for ($i = 0, $n = \count($nodes) - 1; $i < $n; $i++) {
            if (\is_object($node)) {
                if (!isset($node->{$nodes[$i]})) {
                    continue;
                }

                $parent = &$node;
                $node   = $node->{$nodes[$i]};

                continue;
            }

            if (\is_array($node)) {
                if (!isset($node[$nodes[$i]])) {
                    continue;
                }

                $parent = &$node;
                $node   = $node[$nodes[$i]];

                continue;
            }
        }

        // Get the old value if exists so we can return it
        switch (true) {
            case \is_object($node):
                $result = $node->{$nodes[$i]} ? $node->{$nodes[$i]} : null;
                unset($parent->{$nodes[$i]});
                break;

            case \is_array($node):
                $result = $node[$nodes[$i]] ? $node[$nodes[$i]] : null;
                unset($parent[$nodes[$i]]);
                break;

            default:
                $result = null;
                break;
        }

        return $result;
    }
}