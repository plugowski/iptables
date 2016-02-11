<?php
namespace plugowski\iptables\Table;

use plugowski\iptables\Chain;
use plugowski\iptables\Command;

/**
 * Class Table
 * @package plugowski\iptables\Table
 */
class Table
{
    const TABLE_RAW = 'raw';
    const TABLE_FILTER = 'filter';
    const TABLE_NAT = 'nat';
    const TABLE_MANGLE = 'mangle';
    const TABLE_SECURITY = 'security';

    /**
     * @var string
     */
    protected $name;
    /**
     * @var string
     */
    protected $raw;
    /**
     * @var Chain[]
     */
    protected $chains = [];

    /**
     * @return string
     */
    public function getRaw()
    {
        return $this->raw;
    }

    /**
     * @param string $raw
     */
    public function setRaw($raw)
    {
        $this->raw = $raw;
    }

    /**
     * @param Chain $chain
     */
    public function addChain(Chain $chain)
    {
        $this->chains[$chain->getName()] = $chain;
    }

    /**
     * @param Chain $chain
     * @return string
     * @throws \Exception
     */
    public function createChain(Chain $chain)
    {
        $this->chains[$chain->getName()] = $chain;
        $rulesCounter = count($chain->getRulesList());

        $command = new Command($this->name);
        if (1 < $rulesCounter) {
            throw new \Exception('Maximum number Rules on creation is 1.');
        } else if (1 === $rulesCounter) {
            $command->setOptions((string)current($chain->getRulesList()));
        }

        return $command->createChain($chain->getName());
    }

    /**
     * @param string $name
     * @return string
     * @throws \Exception
     */
    public function deleteChain($name)
    {
        $chain = $this->getChainByName($name);
        unset($this->chains[$name]);

        return (new Command($this->name))
            ->deleteChain($chain->getName());
    }

    /**
     * @return Chain[]
     */
    public function getChainsList()
    {
        return $this->chains;
    }

    /**
     * @param string $name
     * @return Chain
     * @throws \Exception
     */
    public function getChainByName($name)
    {
        foreach ($this->chains as $chain) {
            if ($name === $chain->getName()) {
                return $chain;
            }
        }
        throw new \Exception('Chain not found.');
    }

    /**
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }
}