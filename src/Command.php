<?php
namespace plugowski\iptables;

/**
 * Class Command
 * @package plugowski\Iptables
 */
class Command
{
    /**
     * @var array
     */
    private $options = [];
    /**
     * @var string|null
     */
    private $rawOptions;
    /**
     * @var array
     */
    private $tcpFlags = ['ACK', 'FIN', 'PSH', 'RST', 'SYN', 'URG', 'ALL', 'NONE'];
    /**
     * @var array
     */
    private $matchModules = ['limit', 'mac', 'state', 'mark', 'recent'];
    /**
     * @var string
     */
    private $cmd;
    /**
     * @var string
     */
    private $table;

    /**
     * Command constructor.
     * @param $table
     */
    public function __construct($table)
    {
        $this->table = $table;
    }

    /**
     * Append rule to chain - on the end
     *
     * @param string $chainName
     * @return string
     */
    public function appendRule($chainName)
    {
        $this->cmd = '-A ' . $chainName;
        return (string)$this;
    }

    /**
     * Delete single rule by index
     *
     * @param string $chainName
     * @param int $ruleNum
     * @return string
     */
    public function deleteRule($chainName, $ruleNum)
    {
        $this->cmd = '-D ' . $chainName . ' ' . $ruleNum;
        return (string)$this;
    }

    /**
     * Replace existing rule by index
     *
     * @param string $chainName
     * @param int $ruleNum
     * @return string
     */
    public function replaceRule($chainName, $ruleNum)
    {
        $this->cmd = '-R ' . $chainName . ' ' . $ruleNum;
        return (string)$this;
    }

    /**
     * Inserting new rule on specified position (move other rules)
     *
     * @param $chainName
     * @param int $ruleNum
     * @return string
     */
    public function insertRule($chainName, $ruleNum = 1)
    {
        $this->cmd = '-I ' . $chainName . ' ' . $ruleNum;
        return (string)$this;
    }

    /**
     * Flush specified chain (remove all rules)
     *
     * @param string $chainName
     * @return string
     */
    public function flushChain($chainName)
    {
        $this->cmd = '-F ' . $chainName;
        $this->cleanOptions();
        return (string)$this;
    }

    /**
     * Create new custom chain
     *
     * @param string $chainName
     * @return string
     */
    public function createChain($chainName)
    {
        $this->cmd = '-N ' . $chainName;
        return (string)$this;
    }

    /**
     * Delete custom chain - there should not be any references
     *
     * @param string $chainName
     * @return string
     */
    public function deleteChain($chainName)
    {
        $this->cmd = '-X ' . $chainName;
        $this->cleanOptions();
        return (string)$this;
    }


    /**
     * Rename current chain
     *
     * @param string $chainName
     * @param string $newName
     * @return string
     */
    public function renameChain($chainName, $newName)
    {
        $this->cmd = '-E ' . $chainName . ' ' . $newName;
        $this->cleanOptions();
        return (string)$this;
    }

    /**
     * Clean options to prevent generate wrong commands
     */
    private function cleanOptions()
    {
        $this->options = [];
        $this->rawOptions = null;
    }

    /**
     * @param string $protocol
     * @param string|null $sourcePort
     * @param string|null $destinationPort
     * @param array|null $tcpFlags
     * @return $this
     * @throws \Exception
     */
    public function setProtocol($protocol, $sourcePort = null, $destinationPort = null, $tcpFlags = null)
    {
        $this->options['--proto'] = $protocol;
        if (in_array($protocol, ['tcp', 'udp']) && !is_null($sourcePort)) {
            $this->options['--proto'] .= ' --source-port ' . $sourcePort;
        }
        if (in_array($protocol, ['tcp', 'udp']) && !is_null($destinationPort)) {
            $this->options['--proto'] .= ' --destination-port ' . $destinationPort;
        }
        if ('tcp' == $protocol && is_array($tcpFlags)) {
            $diff = array_diff($tcpFlags, $this->tcpFlags);
            if (!empty($diff)) {
                throw new \Exception('Unexpected tcp-flags: ' . implode($diff));
            }
            $this->options['--proto'] .= ' --tcp-flags ' . implode(',', $tcpFlags);
        }
        return $this;
    }

    /**
     * @param string $value
     * @return $this
     */
    public function setSource($value)
    {
        $this->options['--source'] = $value;
        return $this;
    }

    /**
     * @param string $value
     * @return $this
     */
    public function setDestination($value)
    {
        $this->options['--destination'] = $value;
        return $this;
    }

    /**
     * @param string $jump
     * @param array|null $params
     * @return $this
     * @throws \Exception
     */
    public function setJump($jump, array $params = null)
    {
        $this->options['--jump'] = $jump;

        // todo: validate if all required params passed:
        // MARK --set-mark 99
        // DNAT --to-destination 10.10.10.1
        // DSCP --set-dscp [0-63]
        if (!empty($params)) {
            foreach ($params as $name => $value) {
                $this->options['--jump'] .= ' --' . $name . ' ' . $value;
            }
        }

        return $this;
    }

    /**
     * @param string $module
     * @param array $params
     * @return $this
     * @throws \Exception
     */
    public function setMatch($module, array $params)
    {
        if (!in_array($module, $this->matchModules)) {
            throw new \Exception('Invalid module: ' . $module);
        }

        $match = $module;
        foreach ($params as $name => $value) {
            $key = '--' . $module . ($name != $module ? '-' . $name : '');
            $match .= ' ' . $key . ' ' . $value;
        }

        $this->options['--match'] = $match;
        return $this;
    }

    public function setInput($value)
    {
        $this->options['--in-interface'] = $value;
        return $this;
    }

    public function setOutput($value)
    {
        $this->options['--out-interface'] = $value;
        return $this;
    }

    /**
     * @param string $options
     * @return $this
     */
    public function setOptions($options)
    {
        $this->rawOptions = $options;
        return $this;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        $cmd = '';
        if (!is_null($this->cmd)) {
            $cmd .= 'iptables ';
            $cmd .= $this->cmd;
            $cmd .= ' -t ' . $this->table;
        }

        if (!is_null($this->rawOptions)) {
            return $cmd . ' ' . $this->rawOptions;
        }

        foreach ($this->options as $k => $value) {
            if (is_scalar($value)) {
                $cmd .= ' ' . $k . ' ' . $value;
            } else {
                foreach ($value as $option) {
                    $cmd .= ' ' . $k . ' ' . $option;
                }
            }
        }
        return $cmd;
    }
}