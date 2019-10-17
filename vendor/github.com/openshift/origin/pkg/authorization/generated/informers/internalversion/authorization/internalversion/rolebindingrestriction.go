// Code generated by informer-gen. DO NOT EDIT.

package internalversion

import (
	time "time"

	authorization "github.com/openshift/origin/pkg/authorization/apis/authorization"
	internalinterfaces "github.com/openshift/origin/pkg/authorization/generated/informers/internalversion/internalinterfaces"
	internalclientset "github.com/openshift/origin/pkg/authorization/generated/internalclientset"
	internalversion "github.com/openshift/origin/pkg/authorization/generated/listers/authorization/internalversion"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// RoleBindingRestrictionInformer provides access to a shared informer and lister for
// RoleBindingRestrictions.
type RoleBindingRestrictionInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() internalversion.RoleBindingRestrictionLister
}

type roleBindingRestrictionInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewRoleBindingRestrictionInformer constructs a new informer for RoleBindingRestriction type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewRoleBindingRestrictionInformer(client internalclientset.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredRoleBindingRestrictionInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredRoleBindingRestrictionInformer constructs a new informer for RoleBindingRestriction type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredRoleBindingRestrictionInformer(client internalclientset.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.Authorization().RoleBindingRestrictions(namespace).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.Authorization().RoleBindingRestrictions(namespace).Watch(options)
			},
		},
		&authorization.RoleBindingRestriction{},
		resyncPeriod,
		indexers,
	)
}

func (f *roleBindingRestrictionInformer) defaultInformer(client internalclientset.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredRoleBindingRestrictionInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *roleBindingRestrictionInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&authorization.RoleBindingRestriction{}, f.defaultInformer)
}

func (f *roleBindingRestrictionInformer) Lister() internalversion.RoleBindingRestrictionLister {
	return internalversion.NewRoleBindingRestrictionLister(f.Informer().GetIndexer())
}
