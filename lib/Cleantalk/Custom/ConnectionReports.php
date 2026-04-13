<?php

namespace Cleantalk\Custom;

final class ConnectionReports
{
    const REPORT_LIFE_DAYS = 7;
    const MAX_REPORTS_COUNT = 10;

    /**
     * @param array $connection_reports
     * @param bool $success
     * @param string $lib_report
     * @return array
     */
    static function add($connection_reports, $success, $lib_report = 'no lib report')
    {
        $connection_reports = self::validate($connection_reports);
        $connection_reports = self::filter($connection_reports);

        $page_url = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'unknown REQUEST_URI';
        $page_url = substr($page_url, 0, 1000);

        if (!$success) {
            $connection_reports['negative']++;
            $connection_reports['negative_report'][] = array(
                'date' => time(),
                'page_url' => $page_url,
                'lib_report' => is_string($lib_report) ? $lib_report : 'unknown lib report',
            );

            // Trim negative reports to max count
            $connection_reports['negative_report'] = self::trimReportsByCount(
                $connection_reports['negative_report'],
                self::MAX_REPORTS_COUNT
            );
            $connection_reports['negative'] = count($connection_reports['negative_report']);
        } else {
            $connection_reports['success']++;
            $connection_reports['success_report'][] = array(
                'date' => time(),
            );

            // Trim success reports to max count
            $connection_reports['success_report'] = self::trimReportsByCount(
                $connection_reports['success_report'],
                self::MAX_REPORTS_COUNT
            );
            $connection_reports['success'] = count($connection_reports['success_report']);
        }

        return $connection_reports;
    }

    /**
     * Trim reports array to specified count, keeping the newest records
     *
     * @param array $reports
     * @param int $maxCount
     * @return array
     */
    private static function trimReportsByCount($reports, $maxCount)
    {
        if (count($reports) <= $maxCount) {
            return $reports;
        }

        // Sort by date descending and take first N
        usort($reports, function($a, $b) {
            return (int)$b['date'] - (int)$a['date'];
        });

        $reports = array_slice($reports, 0, $maxCount);

        // Reverse to get ascending order (oldest first)
        return array_reverse($reports);
    }

    /**
     * @param array $connection_reports
     * @param string $mailfrom
     * @param callable $mail_provider
     * @return bool
     */
    static function sendMail($connection_reports, $mailfrom, $mail_provider = null)
    {
        $connection_reports = self::validate($connection_reports);
        if (empty($connection_reports['negative_report'])) {
            return false;
        }
        $to      = "pluginreports@cleantalk.org";
        $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'unknown host';
        $subject = "CleanTalk Antispam for Joomla: connection report for " . $host;

        $headers = "Content-type: text/html; charset=utf-8 \r\n";
        $headers .= "From: " . $mailfrom . "\r\n";
        $headers .= "MIME-Version: 1.0\r\n";

        $message = self::prepareEmailBody($connection_reports);
        if (null !== $mail_provider) {
            return @call_user_func($mail_provider, [$to, $subject, $message, $headers]);
        } else {
            return @mail($to, $subject, $message, $headers);
        }
    }

    static function prepareEmailBody($connection_reports)
    {
        $first_success = time();
        if (
            isset($connection_reports['success_report'][0]['date']) &&
            is_numeric($connection_reports['success_report'][0]['date'])
        ) {
            $first_success = (int)$connection_reports['success_report'][0]['date'];
        }

        $first_negative = time();
        if (
            isset($connection_reports['negative_report'][0]['date']) &&
            is_numeric($connection_reports['negative_report'][0]['date'])
        ) {
            $first_negative = (int)$connection_reports['negative_report'][0]['date'];
        }
        $min_date = min($first_success, $first_negative);
        $count_negative_text = $connection_reports['negative'] === self::MAX_REPORTS_COUNT
            ? $connection_reports['negative'] . '+'
            : $connection_reports['negative'];
        $count_success_text = $connection_reports['success'] === self::MAX_REPORTS_COUNT
            ? $connection_reports['success'] . '+'
            : $connection_reports['success'];
        $total = $connection_reports['negative'] + $connection_reports['success'];
        $count_total_text = ($connection_reports['negative'] === self::MAX_REPORTS_COUNT ||
            $connection_reports['success'] === self::MAX_REPORTS_COUNT)
            ? $total . '+'
            : $total;

        $message = '
            <html lang="en">
                <head>
                    <title>Connection Report</title>
                    <style>
                        table { border-collapse: collapse; width: 100%; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f2f2f2; }
                        tr:nth-child(even) { background-color: #f9f9f9; }
                    </style>
                </head>
                <body>
                    <p>From '
            . date("Y-m-d H:i:s", $min_date)
            . ' to ' . date("Y-m-d H:i:s")
            . ' has been made '
            . $count_total_text
            . ' calls, where '
            . $count_success_text
            . ' were success and '
            . $count_negative_text
            . ' were negative</p>';

        if (!empty($connection_reports['negative_report'])) {
            $message .= '
                    <p><strong>Negative report (last ' . count($connection_reports['negative_report']) . ' records):</strong></p>
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Date</th>
                                <th>Page URL</th>
                                <th>Library report</th>
                            </tr>
                        </thead>
                        <tbody>';

            foreach ($connection_reports['negative_report'] as $key => $report) {
                $message .= "
                            <tr>
                                <td>" . ($key + 1) . ".</td>
                                <td>" . htmlspecialchars(date("Y-m-d H:i:s", (int)$report['date'])) . "</td>
                                <td>" . htmlspecialchars($report['page_url'], ENT_QUOTES, 'UTF-8') . "</td>
                                <td>" . htmlspecialchars($report['lib_report']) . "</td>
                            </tr>";
            }

            $message .= '
                        </tbody>
                    </table>';
        } else {
            $message .= '<p>No negative reports in the selected period.</p>';
        }

        $message .= '
                </body>
            </html>';
        return $message;
    }

    /**
     * @param $connection_reports
     * @return array
     */
    static function filter($connection_reports)
    {
        $at_least = time() - self::REPORT_LIFE_DAYS * 24 * 60 * 60;

        // Filter success reports by age
        $success_cleared = array();
        foreach ($connection_reports['success_report'] as $report) {
            if ($report['date'] > $at_least) {
                $success_cleared[] = $report;
            }
        }

        // Apply max count limit to success reports
        $success_cleared = self::trimReportsByCount($success_cleared, self::MAX_REPORTS_COUNT);

        // Filter negative reports by age
        $negative_cleared = array();
        foreach ($connection_reports['negative_report'] as $report) {
            if ($report['date'] > $at_least) {
                $negative_cleared[] = $report;
            }
        }

        // Apply max count limit to negative reports
        $negative_cleared = self::trimReportsByCount($negative_cleared, self::MAX_REPORTS_COUNT);

        $connection_reports['success'] = count($success_cleared);
        $connection_reports['success_report'] = $success_cleared;
        $connection_reports['negative'] = count($negative_cleared);
        $connection_reports['negative_report'] = $negative_cleared;

        return $connection_reports;
    }

    /**
     * @return array
     */
    static function getClearReports()
    {
        return array(
            'success' => 0,
            'negative' => 0,
            'negative_report' => array(),
            'success_report' => array()
        );
    }

    /**
     * @param array|null $connection_reports
     * @return array
     */
    static function validate($connection_reports)
    {
        if (empty($connection_reports) || !is_array($connection_reports)) {
            return self::getClearReports();
        }

        // Initialize missing keys
        if (!isset($connection_reports['success_report']) || !is_array($connection_reports['success_report'])) {
            $connection_reports['success_report'] = array();
        }

        if (!isset($connection_reports['negative_report']) || !is_array($connection_reports['negative_report'])) {
            $connection_reports['negative_report'] = array();
        }

        if (
            !isset($connection_reports['success']) ||
            !is_numeric($connection_reports['success']) ||
            $connection_reports['success'] !== count($connection_reports['success_report'])
        ) {
            $connection_reports['success'] = count($connection_reports['success_report']);
        }

        if (
            !isset($connection_reports['negative']) ||
            !is_numeric($connection_reports['negative']) ||
            $connection_reports['negative'] !== count($connection_reports['negative_report'])
        ) {
            $connection_reports['negative'] = count($connection_reports['negative_report']);
        }

        return $connection_reports;
    }
}
