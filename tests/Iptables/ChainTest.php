<?php
namespace Iptables;

use PHPUnit_Framework_TestCase;
use plugowski\iptables\Chain;
use plugowski\iptables\Rule;
use plugowski\iptables\Table\Table;

/**
 * Class ChainTest
 */
class ChainTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function shouldCreateCorrectChainObject()
    {
        $chain = $this->getExampleChain();
        $this->assertEquals('internet', $chain->getName());
        $this->assertEquals('DROP', $chain->getPolicy());
        $this->assertEquals([], $chain->getRulesList());
    }

    /**
     * @test
     */
    public function shouldAddRuleToChain()
    {
        $chain = $this->getExampleChain();
        $chain->appendRule(new Rule('ACCEPT', 'tcp'));

        $this->assertEquals(1, count($chain->getRulesList()));

        $chain->appendRule(new Rule('DROP', 'udp', '127.0.0.1'));
        $chain->appendRule(new Rule('wanout', 'all', '127.0.0.1', '127.22.22.22'));

        $this->assertEquals(' --proto udp --source 127.0.0.1 --jump DROP', (string)$chain->getRulesList()[2]);
        $this->assertEquals(' --source 127.0.0.1 --destination 127.22.22.22 --jump wanout', (string)$chain->getRulesList()[3]);

        $chain->deleteRule(2);
        $this->assertEquals(' --source 127.0.0.1 --destination 127.22.22.22 --jump wanout', (string)$chain->getRulesList()[2]);
    }

    /**
     * @test
     */
    public function shouldInsertRule()
    {
        $chain = $this->getExampleChain();
        $chain->appendRule(new Rule('ACCEPT', 'tcp'));
        $chain->appendRule(new Rule('DROP', 'tcp'));
        $chain->appendRule(new Rule('something', 'tcp'));

        $expected = ' --proto tcp --jump DROP';
        $this->assertEquals($expected, (string)$chain->getRulesList()[2]);
        $this->assertEquals(3, count($chain->getRulesList()));

        $chain->insertRule(new Rule('INSERT', 'tcp'), 2);

        $expected2 = ' --proto tcp --jump INSERT';
        $this->assertEquals($expected2, (string)$chain->getRulesList()[2]);
        $this->assertEquals(4, count($chain->getRulesList()));
    }

    /**
     * @test
     */
    public function shouldReplaceRule()
    {
        $chain = $this->getExampleChain();
        $chain->appendRule(new Rule('ACCEPT', 'tcp'));
        $chain->appendRule(new Rule('DROP', 'tcp'));

        $expected = ' --proto tcp --jump DROP';
        $this->assertEquals($expected, (string)$chain->getRulesList()[2]);
        $this->assertEquals(2, count($chain->getRulesList()));

        $chain->replaceRule(new Rule('INSERT', 'tcp'), 2);

        $expected2 = ' --proto tcp --jump INSERT';
        $this->assertEquals($expected2, (string)$chain->getRulesList()[2]);
        $this->assertEquals(2, count($chain->getRulesList()));
    }

    /**
     * @test
     */
    public function shouldFlushChain()
    {
        $chain = $this->getExampleChain();
        $chain->appendRule(new Rule('ACCEPT', 'tcp'));
        $chain->appendRule(new Rule('DROP', 'udp', '127.0.0.1'));
        $chain->appendRule(new Rule('wanout', 'all', '127.0.0.1', '127.22.22.22'));

        $this->assertEquals(3, count($chain->getRulesList()));

        $cmd = $chain->flush();

        $expected = 'iptables -F internet -t mangle';
        $this->assertEquals(0, count($chain->getRulesList()));
        $this->assertEquals($expected, $cmd);
    }

    /**
     * @test
     */
    public function shouldChangeNameOfChain()
    {
        $chain = $this->getExampleChain();

        $this->assertEquals('internet', $chain->getName());

        $cmd = $chain->rename('WAN');

        $expected = 'iptables -E internet WAN -t mangle';
        $this->assertEquals('WAN', $chain->getName());
        $this->assertEquals($expected, $cmd);
    }

    private function getExampleChain()
    {
        return new Chain('internet', Table::TABLE_MANGLE, 'DROP');
    }
}