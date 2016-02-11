<?php
namespace plugowski\iptables;

use plugowski\iptables\Table\Table;

/**
 * Class Iptables
 */
class IptablesService
{
    /**
     * @var Table[]
     */
    private $tables;

    /**
     * Iptables constructor.
     */
    public function __construct()
    {
    }

    /**
     * Parse raw iptables data into objects.
     * $rawData is a raw dump of: `iptables -nL --line-numbers -t TABLENAME`
     *
     * @param Table $table
     * @return Chain[]
     */
    public function parseIptablesChains(Table $table)
    {
        $data = explode("\n", $table->getRaw());

        $patterns = [
            'chain' => '/(?:Chain\s)
                        (?<chain>[^\s]+)
                        (?:.*\()
                        (?<policy>.*)
                        (?:\).*)/x',

            'rule' => '/(?<id>\d+)\s+
                        (?<target>\w+)\s+
                        (?<protocol>\w+)\s+
                        (?<opt>[\w-]+)\s+
                        (?<source>[0-9\.\/]+)\s+
                        (?<destination>[0-9\.\/]+)\s+
                        ?(?<options>.*)/x'
        ];

        foreach ($data as $row) {
            if (preg_match($patterns['chain'], $row, $out)) {
                $chain = new Chain($out['chain'], $table->getName(), $out['policy']);
                $table->addChain($chain);
                $this->tables[$table->getName()] = $table;
            }

            if (isset($chain) && preg_match($patterns['rule'], $row, $out)) {
                $rule = new Rule($out['target'], $out['protocol'], $out['source'], $out['destination'], trim($out['options']));
                $rule->setNum($out['id']);
                $chain->insertRule($rule, $out['id']);
            }
        }

        return $table->getChainsList();
    }
}