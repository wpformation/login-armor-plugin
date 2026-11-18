<?php
/**
 * Media activity logger.
 *
 * Tracks: media_uploaded, media_updated, media_deleted.
 *
 * @package LoginArmor\ActivityLog\Loggers
 * @since   2.1.0
 */

namespace LoginArmor\ActivityLog\Loggers;

use LoginArmor\ActivityLog\ActivityLogger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MediaLogger extends ActivityLogger {

	public function get_key(): string {
		return 'media';
	}

	public function get_label(): string {
		return 'Media';
	}

	public function register(): void {
		add_action( 'add_attachment', [ $this, 'on_upload' ] );
		add_action( 'attachment_updated', [ $this, 'on_updated' ], 10, 3 );
		add_action( 'delete_attachment', [ $this, 'on_delete' ], 10, 2 );
	}

	// Callbacks untyped with defaults: media hooks are re-fired by
	// import/offload plugins with degraded arity or types.

	public function on_upload( $post_id = 0 ): void {
		$post_id = (int) $post_id;
		$post    = $post_id > 0 ? get_post( $post_id ) : null;
		if ( ! $post ) {
			return;
		}
		$filename = basename( get_attached_file( $post_id ) ?: $post->post_title );
		$this->log( 'media_uploaded', 'media', $post_id, $filename,
			sprintf( 'File "%s" uploaded.', $filename ) );
	}

	public function on_updated( $post_id = 0, $post_after = null, $post_before = null ): void {
		$post_id = (int) $post_id;
		if ( $post_id <= 0 || ! $post_after instanceof \WP_Post ) {
			return;
		}
		$filename = basename( get_attached_file( $post_id ) ?: $post_after->post_title );
		$this->log( 'media_updated', 'media', $post_id, $filename,
			sprintf( 'File "%s" metadata updated.', $filename ) );
	}

	public function on_delete( $post_id = 0, $post = null ): void {
		$post_id = (int) $post_id;
		if ( $post_id <= 0 || ! $post instanceof \WP_Post ) {
			return;
		}
		$filename = basename( get_attached_file( $post_id ) ?: $post->post_title );
		$this->log( 'media_deleted', 'media', $post_id, $filename,
			sprintf( 'File "%s" deleted.', $filename ) );
	}
}
