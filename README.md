# Parser iptables

**iptable** library allows you to quick and easy parse and manipulate iptables records via PHP.
As a main feature is parse raw iptable dump and build full objected tree with chains and rules. It moves almost all
functionality which give you _iptables_.

Not all patches are implemented - for my purposes there was no need to do that - but it should be enough for most use
cases.

## Installation

The simpliest way to install iptables is use the composer.

```
composer require plugowski/iptables
```

Of course you can also download that repository and load all classes from src into your project.

## Usage

Parsing raw iptables dump build chains tree connected to one of five default tables in `iptables`.

```php
use plugowski\iptables\IptablesService;
use plugowski\iptables\Table\Table;
use plugowski\iptables\Table\TableFactory;

$iptables = new IptablesService();
$table = (new TableFactory())->build(Table::TABLE_MANGLE);
$table->setRaw(shell_exec('iptables -nL --line-numbers -t ' . Table::TABLE_MANGLE));

$result = $iptables->parseIptablesChains($table);
```

As result of above code you should get `Table` object with `Chain` collection:

```php
$chains = $iptables->getChainsList();
```

## Connections

Each `Table` got `Chains` and each `Chain` got `Rules` with properties which describes all selected options.
Using iptables class you can simply find specified chain and get list of all rules in it.

## Example

Some examples you can check directly in tests. But for quick review I also put it here.

Let's get that iptables settings and we want edit first record - set source to `127.0.0.1`:
```
Chain INPUT (policy DROP) 
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
2    DROP       all  --  0.0.0.0/0            0.0.0.0/0           state INVALID
3    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0           state RELATED,ESTABLISHED
4    DROP       tcp  --  0.0.0.0/0            0.0.0.0/0           tcp dpt:22 state NEW
5    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0           MAC 00:00:00:00:11:22
```

I assume that we already have parsed table under `$result` var, so the easiest way to do that is:

```php
$newRule = new Rule('ACCEPT', 'tcp', '127.0.0.1');
$cmd = $result->getChainByName('INPUT')->replaceRule($newRule, 1);

```
First rule in object has been changed and in result we got command in `$cmd`:

```
iptables -R INPUT 1 -t mangle  --proto tcp --source 127.0.0.1 --jump ACCEPT
```

## Command

Command class allows you to generate plain shell commands to manage iptables (only return as strings without execute!).

```php
// To create shell comand like that:
// iptables -A INPUT -t mangle --match mac --mac-source 11:22:33:aa:bb:cc --jump RETURN

$command = new Command(Table::TABLE_MANGLE);
$cmd = $command->setMatch('mac', ['source' => '11:22:33:aa:bb:cc'])
        ->setJump('RETURN')
        ->append('INPUT');
```
Please make sure that you first set all options (setters like `setMatch()`, `setProtocol()` etc.), and after that call action method, because that methods return
strings so it is imposibble to chaining.