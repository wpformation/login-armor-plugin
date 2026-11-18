<?php
/**
 * Post/Page/CPT activity logger.
 *
 * Tracks: post_created, post_updated, post_trashed, post_restored, post_deleted, post_status_changed.
 *
 * @package LoginArmor\ActivityLog\Loggers
 * @since   2.1.0
 */

namespace LoginArmor\ActivityLog\Loggers;

use LoginArmor\ActivityLog\ActivityLogger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class PostLogger extends ActivityLogger {

	/** @var array<int,bool> Guard against duplicate logging per request. */
	private array $logged_transitions = [];

	public function get_key(): string {
		return 'post';
	}

	public function get_label(): string {
		return 'Posts';
	}

	public function register(): void {
		add_action( 'transition_post_status', [ $this, 'on_transition' ], 10, 3 );
		add_action( 'post_updated', [ $this, 'on_post_updated' ], 10, 3 );
		add_action( 'before_delete_post', [ $this, 'on_before_delete' ], 10, 2 );
	}

	// All hook callbacks below are untyped with defaults: content hooks are
	// re-fired by import/migration plugins with degraded arity or types;
	// strict hints would fatal those flows.

	public function on_transition( $new_status = '', $old_status = '', $post = null ): void {
		if ( ! is_string( $new_status ) || ! is_string( $old_status ) || ! $post instanceof \WP_Post ) {
			return;
		}
		if ( wp_is_post_revision( $post ) || $post->post_type === 'nav_menu_item' ) {
			return;
		}
		if ( $new_status === 'auto-draft' || $old_status === 'auto-draft' ) {
			return;
		}

		if ( isset( $this->logged_transitions[ $post->ID ] ) ) {
			return;
		}

		$type_obj  = get_post_type_object( $post->post_type );
		$type_name = $type_obj ? $type_obj->labels->singular_name : $post->post_type;
		$title     = $post->post_title ?: '(no title)';

		if ( $old_status === 'new' && $new_status !== 'trash' ) {
			$this->logged_transitions[ $post->ID ] = true;
			$this->log( 'post_created', 'post', $post->ID, $title,
				sprintf( '%s "%s" created as %s.', $type_name, $title, $new_status ) );
			return;
		}

		if ( $new_status === 'trash' ) {
			$this->logged_transitions[ $post->ID ] = true;
			$this->log( 'post_trashed', 'post', $post->ID, $title,
				sprintf( '%s "%s" moved to trash.', $type_name, $title ) );
			return;
		}

		if ( $old_status === 'trash' && $new_status !== 'trash' ) {
			$this->logged_transitions[ $post->ID ] = true;
			$this->log( 'post_restored', 'post', $post->ID, $title,
				sprintf( '%s "%s" restored from trash.', $type_name, $title ) );
			return;
		}

		if ( $old_status !== $new_status ) {
			$this->logged_transitions[ $post->ID ] = true;
			$this->log( 'post_status_changed', 'post', $post->ID, $title,
				sprintf( '%s "%s" changed from %s to %s.', $type_name, $title, $old_status, $new_status ) );
		}
	}

	public function on_post_updated( $post_id = 0, $post_after = null, $post_before = null ): void {
		$post_id = (int) $post_id;
		if ( $post_id <= 0 || ! $post_after instanceof \WP_Post || ! $post_before instanceof \WP_Post ) {
			return;
		}
		if ( wp_is_post_revision( $post_id ) || $post_after->post_type === 'nav_menu_item' ) {
			return;
		}
		if ( isset( $this->logged_transitions[ $post_id ] ) ) {
			return;
		}

		if ( $post_before->post_title === $post_after->post_title && $post_before->post_content === $post_after->post_content ) {
			return;
		}

		$type_obj  = get_post_type_object( $post_after->post_type );
		$type_name = $type_obj ? $type_obj->labels->singular_name : $post_after->post_type;
		$title     = $post_after->post_title ?: '(no title)';

		$this->log( 'post_updated', 'post', $post_id, $title,
			sprintf( '%s "%s" updated.', $type_name, $title ) );
	}

	public function on_before_delete( $post_id = 0, $post = null ): void {
		$post_id = (int) $post_id;
		if ( $post_id <= 0 || ! $post instanceof \WP_Post ) {
			return;
		}
		if ( wp_is_post_revision( $post_id ) || $post->post_type === 'nav_menu_item' ) {
			return;
		}
		if ( $post->post_status !== 'trash' ) {
			return;
		}

		$type_obj  = get_post_type_object( $post->post_type );
		$type_name = $type_obj ? $type_obj->labels->singular_name : $post->post_type;
		$title     = $post->post_title ?: '(no title)';

		$this->log( 'post_deleted', 'post', $post_id, $title,
			sprintf( '%s "%s" permanently deleted.', $type_name, $title ) );
	}
}
