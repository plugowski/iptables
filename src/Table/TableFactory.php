<?php
namespace plugowski\iptables\Table;

/**
 * Class TableFactory
 * @package plugowski\iptables\Table
 */
class TableFactory
{
    /**
     * @param string $name
     * @return FilterTable|MangleTable|NatTable|RawTable|SecurityTable
     * @throws \Exception
     */
    public function build($name)
    {
        switch ($name) {
            case Table::TABLE_FILTER :
                return new FilterTable();
            case Table::TABLE_MANGLE :
                return new MangleTable();
            case Table::TABLE_NAT :
                return new NatTable();
            case Table::TABLE_RAW :
                return new RawTable();
            case Table::TABLE_SECURITY :
                return new SecurityTable();
            default :
                throw new \Exception('Not found!');
        }
    }
}