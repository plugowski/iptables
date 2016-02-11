<?php
namespace Iptables;

use PHPUnit_Framework_TestCase;
use plugowski\iptables\Command;
use plugowski\iptables\Table\Table;

/**
 * Class CommandTest
 * @package Iptables
 */
class CommandTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function shouldCreateTcpWithBothPortsCommand()
    {
        $command = (new Command(Table::TABLE_MANGLE))
            ->setProtocol('tcp', '10.10.10.111', '127.0.0.1', ['ACK', 'FIN', 'SYN'])
            ->createChain('test');

        $expected = 'iptables -N test -t mangle --proto tcp --source-port 10.10.10.111 --destination-port 127.0.0.1 --tcp-flags ACK,FIN,SYN';
        $this->assertEquals($expected, $command);
    }

    /**
     * @test
     */
    public function shouldThrowExceptionBecauseOfWrongFlags()
    {
        $this->setExpectedException('\Exception');

        $command = new Command(Table::TABLE_MANGLE);
        $command->setProtocol('tcp', null, '127.0.0.1/0', ['ACK', 'XXX', 'EXT']);
    }

    /**
     * @test
     */
    public function shouldSetSourceAndDestination()
    {
        $command = (new Command(Table::TABLE_MANGLE))
            ->setSource('127.0.0.1')
            ->setDestination('1.0.0.0')
            ->createChain('test');

        $expected = 'iptables -N test -t mangle --source 127.0.0.1 --destination 1.0.0.0';
        $this->assertEquals($expected, $command);
    }

    /**
     * @test
     */
    public function shouldSetInputAndOutput()
    {
        $command = (new Command(Table::TABLE_MANGLE))
            ->setInput('eth0')
            ->setOutput('wl0.1')
            ->createChain('test');

        $expected = 'iptables -N test -t mangle --in-interface eth0 --out-interface wl0.1';
        $this->assertEquals($expected, $command);
    }

    /**
     * @test
     */
    public function shouldCreateNewChainInTable()
    {
        $command = (new Command(Table::TABLE_MANGLE))
            ->createChain('internet');

        $expected = 'iptables -N internet -t mangle';
        $this->assertEquals($expected, $command);
    }

    /**
     * @test
     */
    public function shouldAppendToChainWithCustomJump()
    {
        $command = (new Command(Table::TABLE_MANGLE))
            ->setJump('internet')
            ->appendRule('PREROUTING');

        $expected = 'iptables -A PREROUTING -t mangle --jump internet';
        $this->assertEquals($expected, (string)$command);
    }

    /**
     * @test
     */
    public function shouldReturnByMacAddress()
    {
        $command = (new Command(Table::TABLE_MANGLE))
            ->setMatch('mac', ['source' => '00:00:00:00:00:11'])
            ->setJump('RETURN')
            ->appendRule('internet');

        $expected = 'iptables -A internet -t mangle --match mac --mac-source 00:00:00:00:00:11 --jump RETURN';
        $this->assertEquals($expected, (string)$command);
    }

    /**
     * @test
     */
    public function shouldThrowExceptionBecauseOfWrongMatchModule()
    {
        $this->setExpectedException('\Exception');

        (new Command(Table::TABLE_MANGLE))->setMatch('wrongModule', ['some' => 'data']);
    }

    /**
     * @test
     */
    public function shouldReturnAndJumpWithMark()
    {
        $command = (new Command(Table::TABLE_MANGLE))
            ->setJump('MARK', ['set-mark' => 99])
            ->appendRule('internet');

        $expected = 'iptables -A internet -t mangle --jump MARK --set-mark 99';
        $this->assertEquals($expected, (string)$command);
    }

    /**
     * @test
     */
    public function shouldFlushSpecifiedChain()
    {
        $command = (new Command(Table::TABLE_MANGLE))
            ->flushChain('internet');

        $expected = 'iptables -F internet -t mangle';
        $this->assertEquals($expected, (string)$command);
    }
}