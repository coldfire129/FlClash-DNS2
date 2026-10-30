// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint, type=warning, deprecated_member_use, deprecated_member_use_from_same_package
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of '../dns_protection.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// dart format off
T _$identity<T>(T value) => value;

/// @nodoc
mixin _$DnsProtectionProps {

 int get schemaVersion; bool get enabled; String get proxyTarget; List<String> get upstreams; List<String> get bootstrapServers; bool get verbose;
/// Create a copy of DnsProtectionProps
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$DnsProtectionPropsCopyWith<DnsProtectionProps> get copyWith => _$DnsProtectionPropsCopyWithImpl<DnsProtectionProps>(this as DnsProtectionProps, _$identity);

  /// Serializes this DnsProtectionProps to a JSON map.
  Map<String, dynamic> toJson();


@override
bool operator ==(Object other) {
  final _this = this as DnsProtectionProps;
  return identical(this, other) || (other.runtimeType == runtimeType&&other is DnsProtectionProps&&(identical(other.schemaVersion, _this.schemaVersion) || other.schemaVersion == _this.schemaVersion)&&(identical(other.enabled, _this.enabled) || other.enabled == _this.enabled)&&(identical(other.proxyTarget, _this.proxyTarget) || other.proxyTarget == _this.proxyTarget)&&const DeepCollectionEquality().equals(other.upstreams, _this.upstreams)&&const DeepCollectionEquality().equals(other.bootstrapServers, _this.bootstrapServers)&&(identical(other.verbose, _this.verbose) || other.verbose == _this.verbose));
}

@JsonKey(includeFromJson: false, includeToJson: false)
@override
int get hashCode {
  final _this = this as DnsProtectionProps;
  return Object.hash(runtimeType,_this.schemaVersion,_this.enabled,_this.proxyTarget,const DeepCollectionEquality().hash(_this.upstreams),const DeepCollectionEquality().hash(_this.bootstrapServers),_this.verbose);
}

@override
String toString() {
  final _this = this as DnsProtectionProps;
  return 'DnsProtectionProps(schemaVersion: ${_this.schemaVersion}, enabled: ${_this.enabled}, proxyTarget: ${_this.proxyTarget}, upstreams: ${_this.upstreams}, bootstrapServers: ${_this.bootstrapServers}, verbose: ${_this.verbose})';
}


}

/// @nodoc
abstract mixin class $DnsProtectionPropsCopyWith<$Res>  {
  factory $DnsProtectionPropsCopyWith(DnsProtectionProps value, $Res Function(DnsProtectionProps) _then) = _$DnsProtectionPropsCopyWithImpl;
@useResult
$Res call({
 int schemaVersion, bool enabled, String proxyTarget, List<String> upstreams, List<String> bootstrapServers, bool verbose
});




}
/// @nodoc
class _$DnsProtectionPropsCopyWithImpl<$Res>
    implements $DnsProtectionPropsCopyWith<$Res> {
  _$DnsProtectionPropsCopyWithImpl(this._self, this._then);

  final DnsProtectionProps _self;
  final $Res Function(DnsProtectionProps) _then;

/// Create a copy of DnsProtectionProps
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? schemaVersion = null,Object? enabled = null,Object? proxyTarget = null,Object? upstreams = null,Object? bootstrapServers = null,Object? verbose = null,}) {
  return _then(DnsProtectionProps(
schemaVersion: null == schemaVersion ? _self.schemaVersion : schemaVersion // ignore: cast_nullable_to_non_nullable
as int,enabled: null == enabled ? _self.enabled : enabled // ignore: cast_nullable_to_non_nullable
as bool,proxyTarget: null == proxyTarget ? _self.proxyTarget : proxyTarget // ignore: cast_nullable_to_non_nullable
as String,upstreams: null == upstreams ? _self.upstreams : upstreams // ignore: cast_nullable_to_non_nullable
as List<String>,bootstrapServers: null == bootstrapServers ? _self.bootstrapServers : bootstrapServers // ignore: cast_nullable_to_non_nullable
as List<String>,verbose: null == verbose ? _self.verbose : verbose // ignore: cast_nullable_to_non_nullable
as bool,
  ));
}

}


/// Adds pattern-matching-related methods to [DnsProtectionProps].
extension DnsProtectionPropsPatterns on DnsProtectionProps {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>(TResult Function( _DnsProtectionProps value)?  $default,{required TResult orElse(),}){
final _that = this;
switch (_that) {
case _DnsProtectionProps() when $default != null:
return $default(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>(TResult Function( _DnsProtectionProps value)  $default,){
final _that = this;
switch (_that) {
case _DnsProtectionProps():
return $default(_that);case _:
  throw StateError('Unexpected subclass');

}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>(TResult? Function( _DnsProtectionProps value)?  $default,){
final _that = this;
switch (_that) {
case _DnsProtectionProps() when $default != null:
return $default(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>(TResult Function( int schemaVersion,  bool enabled,  String proxyTarget,  List<String> upstreams,  List<String> bootstrapServers,  bool verbose)?  $default,{required TResult orElse(),}) {final _that = this;
switch (_that) {
case _DnsProtectionProps() when $default != null:
return $default(_that.schemaVersion,_that.enabled,_that.proxyTarget,_that.upstreams,_that.bootstrapServers,_that.verbose);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>(TResult Function( int schemaVersion,  bool enabled,  String proxyTarget,  List<String> upstreams,  List<String> bootstrapServers,  bool verbose)  $default,) {final _that = this;
switch (_that) {
case _DnsProtectionProps():
return $default(_that.schemaVersion,_that.enabled,_that.proxyTarget,_that.upstreams,_that.bootstrapServers,_that.verbose);case _:
  throw StateError('Unexpected subclass');

}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>(TResult? Function( int schemaVersion,  bool enabled,  String proxyTarget,  List<String> upstreams,  List<String> bootstrapServers,  bool verbose)?  $default,) {final _that = this;
switch (_that) {
case _DnsProtectionProps() when $default != null:
return $default(_that.schemaVersion,_that.enabled,_that.proxyTarget,_that.upstreams,_that.bootstrapServers,_that.verbose);case _:
  return null;

}
}

}

/// @nodoc
@JsonSerializable()

class _DnsProtectionProps implements DnsProtectionProps {
  const _DnsProtectionProps({this.schemaVersion = 1, this.enabled = false, this.proxyTarget = '',  List<String> upstreams = const ['https://1.1.1.1/dns-query'],  List<String> bootstrapServers = const ['https://1.1.1.1/dns-query'], this.verbose = false}): _upstreams = upstreams,_bootstrapServers = bootstrapServers;
  factory _DnsProtectionProps.fromJson(Map<String, dynamic> json) => _$DnsProtectionPropsFromJson(json);

@override@JsonKey() final  int schemaVersion;
@override@JsonKey() final  bool enabled;
@override@JsonKey() final  String proxyTarget;
 final  List<String> _upstreams;
@override@JsonKey() List<String> get upstreams {
  if (_upstreams is EqualUnmodifiableListView) return _upstreams;
  // ignore: implicit_dynamic_type
  return EqualUnmodifiableListView(_upstreams);
}

 final  List<String> _bootstrapServers;
@override@JsonKey() List<String> get bootstrapServers {
  if (_bootstrapServers is EqualUnmodifiableListView) return _bootstrapServers;
  // ignore: implicit_dynamic_type
  return EqualUnmodifiableListView(_bootstrapServers);
}

@override@JsonKey() final  bool verbose;

/// Create a copy of DnsProtectionProps
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
_$DnsProtectionPropsCopyWith<_DnsProtectionProps> get copyWith => __$DnsProtectionPropsCopyWithImpl<_DnsProtectionProps>(this, _$identity);

@override
Map<String, dynamic> toJson() {
  return _$DnsProtectionPropsToJson(this, );
}

@override
bool operator ==(Object other) {
    return identical(this, other) || (other.runtimeType == runtimeType&&other is _DnsProtectionProps&&(identical(other.schemaVersion, schemaVersion) || other.schemaVersion == schemaVersion)&&(identical(other.enabled, enabled) || other.enabled == enabled)&&(identical(other.proxyTarget, proxyTarget) || other.proxyTarget == proxyTarget)&&const DeepCollectionEquality().equals(other.upstreams, _upstreams)&&const DeepCollectionEquality().equals(other.bootstrapServers, _bootstrapServers)&&(identical(other.verbose, verbose) || other.verbose == verbose));
}

@JsonKey(includeFromJson: false, includeToJson: false)
@override
int get hashCode {
    return Object.hash(runtimeType,schemaVersion,enabled,proxyTarget,const DeepCollectionEquality().hash(_upstreams),const DeepCollectionEquality().hash(_bootstrapServers),verbose);
}

@override
String toString() {
    return 'DnsProtectionProps(schemaVersion: $schemaVersion, enabled: $enabled, proxyTarget: $proxyTarget, upstreams: $upstreams, bootstrapServers: $bootstrapServers, verbose: $verbose)';
}


}

/// @nodoc
abstract mixin class _$DnsProtectionPropsCopyWith<$Res> implements $DnsProtectionPropsCopyWith<$Res> {
  factory _$DnsProtectionPropsCopyWith(_DnsProtectionProps value, $Res Function(_DnsProtectionProps) _then) = __$DnsProtectionPropsCopyWithImpl;
@override @useResult
$Res call({
 int schemaVersion, bool enabled, String proxyTarget, List<String> upstreams, List<String> bootstrapServers, bool verbose
});




}
/// @nodoc
class __$DnsProtectionPropsCopyWithImpl<$Res>
    implements _$DnsProtectionPropsCopyWith<$Res> {
  __$DnsProtectionPropsCopyWithImpl(this._self, this._then);

  final _DnsProtectionProps _self;
  final $Res Function(_DnsProtectionProps) _then;

/// Create a copy of DnsProtectionProps
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? schemaVersion = null,Object? enabled = null,Object? proxyTarget = null,Object? upstreams = null,Object? bootstrapServers = null,Object? verbose = null,}) {
  return _then(_DnsProtectionProps(
schemaVersion: null == schemaVersion ? _self.schemaVersion : schemaVersion // ignore: cast_nullable_to_non_nullable
as int,enabled: null == enabled ? _self.enabled : enabled // ignore: cast_nullable_to_non_nullable
as bool,proxyTarget: null == proxyTarget ? _self.proxyTarget : proxyTarget // ignore: cast_nullable_to_non_nullable
as String,upstreams: null == upstreams ? _self._upstreams : upstreams // ignore: cast_nullable_to_non_nullable
as List<String>,bootstrapServers: null == bootstrapServers ? _self._bootstrapServers : bootstrapServers // ignore: cast_nullable_to_non_nullable
as List<String>,verbose: null == verbose ? _self.verbose : verbose // ignore: cast_nullable_to_non_nullable
as bool,
  ));
}


}

// dart format on
