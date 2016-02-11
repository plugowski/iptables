<?php
namespace Iptables;

use PHPUnit_Framework_TestCase;
use plugowski\iptables\Chain;
use plugowski\iptables\Rule;
use plugowski\iptables\Table\Table;
use plugowski\iptables\Table\TableFactory;

/**
 * Class TableTest
 * @package Iptables
 */
class TableTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function shouldCreateNewEmptyChain()
    {
        $table = (new TableFactory())->build(Table::TABLE_MANGLE);
        $chain = new Chain('test', Table::TABLE_MANGLE, 'none');
        $table->createChain($chain);

        $this->assertEquals('test', current($table->getChainsList())->getName());
    }

    /**
     * @test
     */
    public function shouldCreateNewChainWithOneRule()
    {
        $table = (new TableFactory())->build(Table::TABLE_MANGLE);
        $chain = new Chain('test', Table::TABLE_MANGLE, 'none');
        $chain->appendRule(new Rule('INPUT', 'tcp'));
        $table->createChain($chain);

        $this->assertEquals('test', current($table->getChainsList())->getName());
    }

    /**
     * @test
     */
    public function shouldThrowExceptionBecauseOfTooManyRules()
    {
        $this->setExpectedException('\Exception');

        $table = (new TableFactory())->build(Table::TABLE_MANGLE);
        $chain = new Chain('test', Table::TABLE_MANGLE, 'none');
        $chain->appendRule(new Rule('INPUT', 'tcp'));
        $chain->appendRule(new Rule('DROP', 'tcp'));
        $table->createChain($chain);
    }

    /**
     * @test
     */
    public function shouldDeleteChainByName()
    {
        $table = (new TableFactory())->build(Table::TABLE_MANGLE);
        $table->createChain(new Chain('test', Table::TABLE_MANGLE, 'none'));
        $table->createChain(new Chain('test2', Table::TABLE_MANGLE, 'none'));

        $cmd = $table->deleteChain('test2');

        $expected = 'iptables -X test2 -t mangle';
        $this->assertEquals(1, count($table->getChainsList()));
        $this->assertEquals($expected, $cmd);
    }

    /**
     * @test
     */
    public function shouldThrowExceptionBecauseOfNotFoundChain()
    {
        $this->setExpectedException('\Exception');

        $table = (new TableFactory())->build(Table::TABLE_MANGLE);
        $table->getChainByName('something');
    }
}