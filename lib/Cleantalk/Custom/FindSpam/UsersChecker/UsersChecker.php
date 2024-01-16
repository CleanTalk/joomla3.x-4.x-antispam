<?php

namespace Cleantalk\Custom\FindSpam\UsersChecker;

use Cleantalk\Common\Cleaner\Sanitize;
use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Custom\FindSpam\UsersChecker\Model\Model;
use JText;

class UsersChecker
{
	/**
	 * @var array
	 */
	private $data;

	/**
	 * @var string
	 */
	private $api_key;

	/**
	 * @var Model
	 */
	private $model;

	/**
	 * @var string
	 */
	private $response;

	/**
	 * Pagination limit
	 * @var int
	 */
	public $limit = 20;

	public function __construct($data)
	{
		$this->data = $data;
		$this->api_key = isset($this->data['api_key']) ? $this->data['api_key'] : '';
		$this->model = new Model();

		$route = isset($this->data['route']) ? Sanitize::sanitize($this->data['route'], 'word') : 'getTabContent';
		$this->response = $this->handleRequest($route);
	}

	public function getResponse()
	{
		return $this->response;
	}

	/**
	 * @param $route
	 *
	 * @return string
	 *
	 * @since 3.3.0
	 */
	private function handleRequest($route)
	{
		switch ($route) {
			case 'delete' :
				return $this->delete($this->data);
			case 'scan' :
				return $this->scan($this->data);
			case 'clearResults' :
				return $this->clearResults();
			case 'getScanResults' :
				return $this->getScanResults(true);
			case 'getTabContent' :
			default :
				return $this->getTabContent();
		}
	}

	private function getTabContent()
	{
		$out = $this->getTabHeader();

		$out .= $this->getScanResults(true);

		$out .= $this->getTabFooter();

		return $out;

	}

	function getScanResults($with_controls = false)
	{
		$spam_total = $this->model->getSpamUsersTotal();
		$page = isset($this->data['page']) && $this->data['page'] ? (int) $this->data['page'] : 1;
		$offset = ( $page - 1 ) * $this->limit;
		$scan_results = $this->model->getScanResults($this->limit, $offset);
		$out = '';

		if ( $scan_results ) {
			if ( $with_controls ) {
				$out .= $this->getButtonsControl();
				if ( $spam_total > $this->limit ) {
					$out .= $this->getPaginationControl($spam_total, $page);
				}
			}
			$out .= $this->getTabResults($scan_results);
		} else {
			$out .= JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_NOUSERSFOUND');
		}

		return $out;
	}

	private function getTabHeader()
	{
		$view_template = file_get_contents(__DIR__ . '/View/UsersCheckerHeader.html');

		$replaces = array(
			'{{tabTitle}}' => JText::_('COM_PLUGINS_CHECKUSERS_FIELDSET_LABEL'),
			'{{totalText}}' => $this->getTotalText(),
			'{{checkingStatus}}' => $this->getCheckingStatus(),
			'{{tip-1}}' => JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_TIP_1'),
			'{{tip-2}}' => JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_TIP_2'),
			'{{tip-3}}' => sprintf(JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_TIP_3'), "<a target='_blank' href='https://cleantalk.org'>Anti-Spam by CleanTalk</a>", "<a target='_blank' href='https://cleantalk.org/blacklists'>blacklist database</a>"),
			'{{buttonText}}' => JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_BUTTON'),
			'{{accurateCheckText}}' => JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_ACCURATE'),
		);

		return str_replace(array_keys($replaces), array_values($replaces), $view_template);
	}

	private function getButtonsControl()
	{
		$view_template = file_get_contents(__DIR__ . '/View/UsersCheckerButtonsControl.html');

		$replaces = array(
			'{{buttonDeleteAll}}' => JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_DELALL'),
			'{{buttonDeleteSelected}}' => JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_DELSEL'),
		);

		return str_replace(array_keys($replaces), array_values($replaces), $view_template);
	}

	private function getPaginationControl($spam_total, $page)
	{
		$pages = $spam_total / $this->limit;

		$pagination_header = file_get_contents(__DIR__ . '/View/Pagination/UsersCheckerPaginationHeader.html');

		$pagination = '';
		$pagination_content = file_get_contents(__DIR__ . '/View/Pagination/UsersCheckerPagination.html');
		for ( $i = 0; $pages > $i; $i++ ) {
			$replaces = array(
				'{{pageNumber}}' => $i + 1,
			);
			if ( $i + 1 === (int) $page ) {
				$replaces['{{active}}'] = 'active';
			} else {
				$replaces['{{active}}'] = '';
			}
			$pagination .= str_replace(array_keys($replaces), array_values($replaces), $pagination_content);
		}


		$pagination_footer = file_get_contents(__DIR__ . '/View/Pagination/UsersCheckerPaginationFooter.html');

		return $pagination_header . $pagination . $pagination_footer;
	}

	private function getTabResults($scan_results)
	{
		$table_header = file_get_contents(__DIR__ . '/View/Results/UsersCheckerResultsHeader.html');
		$table_header_replaces = array(
			'{{tableHeaderUsername}}' => JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_TABLE_USERNAME'),
			'{{tableHeaderJoined}}' => JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_TABLE_JOINED'),
			'{{tableHeaderEmail}}' => JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_TABLE_EMAIL'),
			'{{tableHeaderLastVisit}}' => JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_TABLE_LASTVISIT'),
		);

		$out = str_replace(array_keys($table_header_replaces), array_values($table_header_replaces), $table_header);

		$table_content = file_get_contents(__DIR__ . '/View/Results/UsersCheckerResults.html');

		foreach ($scan_results as $scan_result) {
			$table_content_replaces = array(
				'{{tableId}}' => $scan_result['user_id'],
				'{{tableUsername}}' => $scan_result['username'],
				'{{tableJoined}}' => $scan_result['registerDate'],
				'{{tableEmail}}' => $scan_result['email'],
				'{{tableLastVisit}}' => $scan_result['lastvisitDate'] === '0000-00-00 00:00:00' ? '-' : $scan_result['lastvisitDate'],
			);
			$out .= str_replace(array_keys($table_content_replaces), array_values($table_content_replaces), $table_content);
		}

		$out .= file_get_contents(__DIR__ . '/View/Results/UsersCheckerResultsFooter.html');

		return $out;
	}

	private function getTabFooter()
	{
		return file_get_contents(__DIR__ . '/View/UsersCheckerFooter.html');
	}

	/**
	 * Getting a count of total users of the website and return formatted string about this.
	 *
	 * @return string
	 */
	private function getTotalText()
	{
		$res = $this->model->getUsersCount();

		if ( $res ) {
			$text = sprintf(JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_TOTAL'), '<span>' . $res . '</span>');
		} else {

			$text = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_NO_USERS');
		}

		return $text;
	}

	private function getCheckingStatus()
	{
		/** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
		$storage_handler_class = Mloader::get('StorageHandler');
		$storage_handler_class = new $storage_handler_class();
		$last_users_check_info = $storage_handler_class->getSetting('cleantalk_last_users_check');

		if ( $last_users_check_info ) {
			$message = sprintf(
				JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_LAST_CHECK_INFO'),
				'<spam id="ct_userchecking__checking_date">' . $last_users_check_info['checking_date'] . '</spam>',
				'<spam id="ct_userchecking__checking_count">' . $last_users_check_info['checking_count'] . '</spam>',
				'<spam id="ct_userchecking__found_spam">' . $last_users_check_info['found_spam'] . '</spam>'
			);
		} else {
			$message = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_NOT_CHECKED');
		}
		return $message;
	}

	private function scan($data)
	{
		if( ! $this->api_key ) {
			$output['html']   = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_BADKEY');
			$output['success'] = false;
			$output['end'] = true;
		}

		/** @var \Cleantalk\Common\Api\Api $api_class */
		$api_class = Mloader::get('Api');
		/** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
		$storage_handler_class = Mloader::get('StorageHandler');
		$storage_handler_class = new $storage_handler_class();

		$limit = isset($data['limit']) ? (int) $data['limit'] : 20;
		$offset = isset($data['offset']) ? (int) $data['offset'] : 0;
		$improved_check = isset($data['improved_check']) ? (bool) $data['improved_check'] : false;

		if ( $offset === 0 ) {
			// Reset scan info on the firs iteration
			$scan_info = [
				'checking_date'  => date('M m, Y'),
				'checking_count' => 0,
				'found_spam'     => 0,
			];

			$storage_handler_class->saveSetting('cleantalk_last_users_check', $scan_info);
		}

		$output = [];
		$data = [];
		$spam = [];

		$usersToCheck = $this->model->getUsersToCheck($limit);

		foreach ($usersToCheck as $user)
		{
			if ($improved_check)
			{
				$curr_date          = substr($user['registerDate'], 0, 10) ?: '';
				$data[$curr_date][] = ! empty($user['email']) ? $user['email'] : null;
			} else {
				$data[] = !empty($user['email']) ? $user['email'] : null;
			}
		}

		if ( count($data) === 0 )
		{
			$last_users_check_info = $storage_handler_class->getSetting('cleantalk_last_users_check');
			$stored_checking_count = isset($last_users_check_info['checking_count']) ? $last_users_check_info['checking_count'] : 0;
			$stored_found_spam     = isset($last_users_check_info['found_spam']) ? $last_users_check_info['found_spam'] : 0;

			$output['html']   = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_NOUSERSTOCHECK');
			$output['success'] = true;
			$output['end'] = true;
			$output['checkingCount'] = $stored_checking_count;
			$output['foundedSpam'] = $stored_found_spam;
		} else {
			if ( $improved_check ) {
				foreach ( $data as $date => $values ) {
					$values = implode(',', $values);
					$result = $api_class::methodSpamCheckCms($this->api_key, $values, $date);
				}
			} else {
				$values = implode(',', $data);
				$result = $api_class::methodSpamCheckCms($this->api_key, $values);
			}

			if ( $result ) {
				if ( isset($result['error_message']) ) {
					$output['html']   = 'API error: ' . $result['error_message'];
					$output['success'] = false;
					$output['end'] = true;
				} else {
					foreach ($result as $mail => $value) {
						foreach ($usersToCheck as $user) {
							if ( $user['email'] === $mail ) {
								if ( isset($value['appears']) && $value['appears'] == '1' ) { // Do not use strict comparing here
									$this->model->updateUserMeta((int)$user['id'], 'ct_marked_as_spam', '1');
									$spam[] = $user['email'];
								} else {
									$this->model->updateUserMeta((int)$user['id'], 'ct_marked_as_spam', '0');
								}
							}
						}
					}

					// Store checking stats
					$last_users_check_info = $storage_handler_class->getSetting('cleantalk_last_users_check');

					$stored_checking_count = isset($last_users_check_info['checking_count']) ? $last_users_check_info['checking_count'] : 0;
					$stored_found_spam     = isset($last_users_check_info['found_spam']) ? $last_users_check_info['found_spam'] : 0;

					$scan_info = [
						'checking_date'  => date('M m, Y'),
						'checking_count' => $stored_checking_count + count($data),
						'found_spam'     => $stored_found_spam + count($spam),
					];

					$output['checkingCount'] = $scan_info['checking_count'];
					$output['foundedSpam'] = $scan_info['found_spam'];

					$storage_handler_class->saveSetting('cleantalk_last_users_check', $scan_info);

				}
			} else {
				$output['html']   = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_COMMON_ERROR');
				$output['success'] = false;
				$output['end'] = true;
			}
		}

		if ( ! isset($output['success']) || $output['success'] ) {
			$output['success'] = true;
			$output['offset']  = $offset + $limit;
		}

		return json_encode($output);
	}

	private function clearResults()
	{
		$this->model->clearScanResults();
		return json_encode(array(
			'users_count' => $this->model->getUsersCount(),
			'current_date' => date('M m, Y')
		));
	}

	private function delete($data)
	{
		if ( ! isset($data['ct_del_user_ids']) ) {
			// No selected users
			$output['result'] = 'error';
			$output['data']   = JText::_('PLG_SYSTEM_CLEANTALKANTISPAM_CHECKUSERS_DELCONFIRM_ERROR');
			return json_encode($output);
		}

		$ids = array_map(function($id) {
			return (int) $id;
		}, $data['ct_del_user_ids']);

		$output['result'] = null;
		$output['data']   = null;

		if ( count($ids) ) {
			try {
				$this->model->deleteUsers(implode(',', $ids));
				$output['result'] = 'success';
				$output['data']   = JText::sprintf('PLG_SYSTEM_CLEANTALKANTISPAM_JS_PARAM_SPAMCHECK_USERS_DELDONE', count($data['ct_del_user_ids']));
			}
			catch (\Exception $e) {
				// Database error
				$output['result'] = 'error';
				$output['data']   = $e->getMessage();
				return json_encode($output);
			}
		}

		return json_encode($output);

	}
}
