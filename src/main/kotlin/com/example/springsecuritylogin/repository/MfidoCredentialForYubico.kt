package com.example.springsecuritylogin.repository

import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.Table

/**
 * SpringBootとJPAを使ったEntityクラス
 * @Entity：Entityクラスであることを宣言する
 * @Table：name属性で連携するテーブル名を指定する
 */
@Entity
@Table(name = "M_FIDO_CREDENTIAL_FOR_YUBICO")
data class MfidoCredentialForYubico(
    /**
     *  @Id：主キーに指定する。※複合キーの場合は@EmbeddedIdを使用
     *  @GeneratedValue：主キーの指定をJPAに委ねる
     *  @Column：name属性でマッピングするカラム名を指定する
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="ID")
    var id: Int,

    @Column(name="USER_INTERNAL_ID")
    var userInternalId: String,

    @Column(name="CREDENTIAL_ID")
    var credentialId: String,

    @Column(name="SIGN_COUNT")
    var signCount: Long,

    @Column(name="CREDENTIAL_PUBLIC_KEY")
    var credentialPublicKey: ByteArray,
)
