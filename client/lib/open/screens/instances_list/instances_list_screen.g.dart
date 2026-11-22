// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'instances_list_screen.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(_instancesListData)
final _instancesListDataProvider = _InstancesListDataProvider._();

final class _InstancesListDataProvider
    extends
        $FunctionalProvider<
          AsyncValue<List<_InstanceItemData>>,
          List<_InstanceItemData>,
          Stream<List<_InstanceItemData>>
        >
    with
        $FutureModifier<List<_InstanceItemData>>,
        $StreamProvider<List<_InstanceItemData>> {
  _InstancesListDataProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'_instancesListDataProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$_instancesListDataHash();

  @$internal
  @override
  $StreamProviderElement<List<_InstanceItemData>> $createElement(
    $ProviderPointer pointer,
  ) => $StreamProviderElement(pointer);

  @override
  Stream<List<_InstanceItemData>> create(Ref ref) {
    return _instancesListData(ref);
  }
}

String _$_instancesListDataHash() =>
    r'c9c689e4055abc776a97387cbcf4b6d244b0dfc9';
