<?php

namespace GaussAllianz\ShibbolethGuardBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;

/**
 * This is the class that loads and manages your bundle configuration
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html}
 */
class ShibbolethGuardExtension extends Extension
{
    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $config = $this->processConfiguration($configuration, $configs);
        $loader = new Loader\XmlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.xml');

        if (isset($config['handler_path'])) {
            $container->setParameter('shibboleth_guard.handler_path', $config['handler_path']);
        }
        if (isset($config['session_initiator_path'])) {
            $container->setParameter('shibboleth_guard.session_initiator_path', $config['session_initiator_path']);
        }
        if (isset($config['username_attribute'])) {
            $container->setParameter('shibboleth_guard.username_attribute', $config['username_attribute']);
        }
        if (isset($config['attribute_definitions'])) {
            $container->setParameter('shibboleth_guard.attribute_definitions', $config['attribute_definitions']);
        } else {
            $container->setParameter('shibboleth_guard.attribute_definitions', array());
        }
        if (isset($config['use_headers'])) {
            $container->setParameter('shibboleth_guard.use_headers', $config['use_headers']);
        } else {
            $container->setParameter('shibboleth_guard.use_headers', true);
        }
        if (isset($config['logout_target'])) {
            $container->setParameter('shibboleth_guard.logout_target', $config['logout_target']);
        }
    }
}
