<?php
namespace plugowski\iptables;

/**
 * Class Chain
 */
class Chain
{
    /**
     * @var string
     */
    private $name;
    /**
     * @var string
     */
    private $table;
    /**
     * @var string
     */
    private $policy;
    /**
     * @var Rule[]
     */
    private $rules = [];

    /**
     * Chain constructor.
     * @param string $name
     * @param string $table
     * @param string $policy
     */
    public function __construct($name, $table, $policy)
    {
        $this->name = $name;
        $this->policy = $policy;
        $this->table = $table;
    }

    /**
     * @param Rule $rule
     * @param int $id
     * @return string
     */
    public function insertRule(Rule $rule, $id)
    {
        $tmp = array_slice($this->rules, 0, $id - 1)
            + ['tmp' => $rule]
            + array_slice($this->rules, $id - 2);

        $this->rules = $tmp;
        $this->resetIndexes();

        return (new Command($this->table))
            ->setOptions((string)$rule)
            ->insertRule($this->getName(), $id);
    }

    /**
     * @param Rule $rule
     * @return string
     */
    public function appendRule(Rule $rule)
    {
        $nextId = count($this->rules) + 1;
        $this->rules[$nextId] = $rule;
        $rule->setNum($nextId);

        return (new Command($this->table))
            ->setOptions((string)$rule)
            ->appendRule($this->getName());
    }

    /**
     * @param Rule $rule
     * @param int $id
     * @return string
     */
    public function replaceRule(Rule $rule, $id)
    {
        $this->rules[$id] = $rule;
        $rule->setNum($id);

        return (new Command($this->table))
            ->setOptions((string)$rule)
            ->replaceRule($this->getName(), $id);
    }

    /**
     * @param int $id
     * @return string
     */
    public function deleteRule($id)
    {
        unset($this->rules[$id]);
        $this->resetIndexes();

        return (new Command($this->table))
            ->deleteRule($this->getName(), $id);
    }

    /**
     * @return string
     */
    public function flush()
    {
        $this->rules = [];

        return (new Command($this->table))
            ->flushChain($this->getName());
    }

    /**
     * @param string $newName
     * @return string
     */
    public function rename($newName)
    {
        $oldName = $this->name;
        $this->name = $newName;

        return (new Command($this->table))
            ->renameChain($oldName, $newName);
    }

    /**
     * Reset indexes for rules in specified Chain
     * @return void
     */
    private function resetIndexes()
    {
        $this->rules = array_combine(array_keys(array_fill(1, count($this->rules), null)), $this->rules);

        foreach ($this->rules as $index => $rule) {
            $rule->setNum($index);
        }
    }

    /**
     * @return Rule[]
     */
    public function getRulesList()
    {
        return $this->rules;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @return string
     */
    public function getPolicy()
    {
        return $this->policy;
    }

}