<?php
declare(strict_types=1);

namespace Afosto\Acme\Exception;

use Afosto\Acme\Data\Order;

abstract class AbstractOrderException extends \RuntimeException
{
    private $order;

    public function __construct(Order $order, $message = "", $code = 0, \Throwable $previous = null)
    {
        $this->order = $order;
        parent::__construct($message, $code, $previous);
    }

    public function getOrder(): Order
    {
        return $this->order;
    }
}
