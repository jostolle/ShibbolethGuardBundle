<?php
namespace GaussAllianz\ShibbolethGuardBundle\DependencyInjection;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html#cookbook-bundles-extension-config-class}
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritDoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('shibboleth_guard');

        $rootNode
            ->children()
                ->scalarNode('handler_path')->end()
                ->scalarNode('session_initiator_path')->end()
                ->scalarNode('username_attribute')->end()
                ->scalarNode('use_headers')->end()
                ->scalarNode('logout_target')->end()
            ->end()
            ->fixXmlConfig('attribute_definition')
            ->children()
                ->arrayNode('attribute_definitions')
                    ->useAttributeAsKey('alias')
                    ->prototype('array')
                        ->children()
                            ->scalarNode('header')->isRequired()->end()
                            ->scalarNode('server')->defaultValue(null)->end()
                            ->booleanNode('multivalue')->defaultValue(false)->end()
                            ->scalarNode('charset')->defaultValue('UTF-8')->end()
                        ->end()
                ->end()
             ->end()
        ;
        return $treeBuilder;
    }
}
