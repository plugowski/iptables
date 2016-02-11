<?php
namespace Iptables;

use PHPUnit_Framework_TestCase;
use plugowski\iptables\Rule;

/**
 * Class RuleTest
 * @package Iptables
 */
class RuleTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function shouldCreateRule()
    {
        $rule = new Rule('ACCEPT', 'tcp', '127.0.0.1');
        $expected = ' --proto tcp --source 127.0.0.1 --jump ACCEPT';

        $this->assertEquals($expected, (string)$rule);

        $rule = new Rule('ACCEPT', 'tcp', '127.0.0.1', '0.0.0.0/0', ['--match' => ['mac --mac-source 00:11:22:33:44:55:66']]);
        $expected = ' --proto tcp --source 127.0.0.1 --match mac --mac-source 00:11:22:33:44:55:66 --jump ACCEPT';

        $this->assertEquals($expected, (string)$rule);

        $rule->setNum(2);
        $this->assertEquals(2, $rule->getNum());
    }
}