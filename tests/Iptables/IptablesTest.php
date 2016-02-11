<?php
namespace Iptables;

use PHPUnit_Framework_TestCase;
use plugowski\iptables\IptablesService;
use plugowski\iptables\Table\Table;
use plugowski\iptables\Table\TableFactory;

/**
 * Class IptablesTest
 */
class IptablesTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function shouldGenerateIptables()
    {
        $iptables = new IptablesService();
        $table = (new TableFactory())->build(Table::TABLE_MANGLE);
        $raw = file_get_contents(__DIR__ . '/sample_iptables.txt');
        $table->setRaw($raw);
        // $table->setRaw(shell_exec('iptables -nL --line-numbers -t ' . Table::TABLE_MANGLE));

        $iptables->parseIptablesChains($table);

        $this->assertEquals('INPUT', $table->getChainByName('INPUT')->getName());
        $this->assertEquals(strlen($raw), strlen($table->getRaw()));
    }

    /**
     * @test
     */
    public function shouldThrowNotFoundException()
    {
        $this->setExpectedException('\Exception');
        $iptables = new IptablesService();
        $table = (new TableFactory())->build(Table::TABLE_MANGLE);
        $raw = file_get_contents(__DIR__ . '/sample_iptables.txt');
        $table->setRaw($raw);

        $iptables->parseIptablesChains($table);
        $table->getChainByName('NotFound');
    }

    /**
     * @test
     */
    public function shouldTestAllTableTypes()
    {
        $table = (new TableFactory())->build(Table::TABLE_MANGLE);
        $this->assertEquals(Table::TABLE_MANGLE, $table->getName());

        $table = (new TableFactory())->build(Table::TABLE_FILTER);
        $this->assertEquals(Table::TABLE_FILTER, $table->getName());

        $table = (new TableFactory())->build(Table::TABLE_NAT);
        $this->assertEquals(Table::TABLE_NAT, $table->getName());

        $table = (new TableFactory())->build(Table::TABLE_RAW);
        $this->assertEquals(Table::TABLE_RAW, $table->getName());

        $table = (new TableFactory())->build(Table::TABLE_SECURITY);
        $this->assertEquals(Table::TABLE_SECURITY, $table->getName());
    }

    /**
     * @test
     */
    public function shouldThrowExceptionTryingUseNotExistingTableInFactory()
    {
        $this->setExpectedException('\Exception');
        (new TableFactory())->build('NotExisting');
    }
}