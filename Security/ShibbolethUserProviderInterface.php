<?php
namespace GaussAllianz\ShibbolethGuardBundle\Security;

use Symfony\Component\Security\Core\User\UserProviderInterface;

interface ShibbolethUserProviderInterface extends UserProviderInterface
{
    public function createUser(array $credentials);
}
