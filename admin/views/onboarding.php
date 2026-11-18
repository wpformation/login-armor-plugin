<?php
/**
 * Onboarding wizard: the screen that decides how a site starts, and the one
 * that says what actually happened.
 *
 * Reached by the one-shot redirect after a fresh activation, and again at any
 * time from "Review the setup assistant" on the Settings tab. Because it is
 * revisitable, it cannot be written as a first run: until 2.7.1 it showed the
 * same two cards to an untouched site and to a fully configured one, so the
 * only way to know whether the recommended protections were on was to go and
 * look at every one of them. It now reads the real state on every render
 * (SafeBaseline::preview(), which writes nothing) and prints it line by line.
 *
 * Applying no longer redirects on trust either. SafeBaseline::apply() has
 * always returned what it switched on and the browser has always thrown that
 * away; the report now lands on this very screen, each line linking to the
 * setting it names, before the administrator moves on.
 *
 * Self-contained: it ships its own small inline script so it does not depend
 * on the main settings bundle.
 *
 * @package LoginArmor
 *
 * @var string $admin_nonce login_armor_admin_action nonce.
 * @var string $ajax_url    admin-ajax.php URL.
 * @var bool   $first_run   True only the first time the wizard is displayed.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
//
// Same line as every other view in admin/views/. These files are included from
// inside a method, so their variables are locals, but a sniff reading one file
// on its own cannot see that and reports them as unprefixed globals. 2.7.1
// rewrote this view and the line was lost with the old body, which put twelve
// warnings back into a build whose baseline is empty.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$la_ob_ready    = class_exists( '\LoginArmor\Setup\SafeBaseline' );
$la_ob_items    = $la_ob_ready ? \LoginArmor\Setup\SafeBaseline::preview() : array();
$la_ob_manual   = $la_ob_ready ? \LoginArmor\Setup\SafeBaseline::deliberate_modules() : array();
$la_ob_settings = admin_url( 'admin.php?page=login-armor&tab=settings' );
$la_ob_first    = ! isset( $first_run ) || (bool) $first_run;

// How many lines the Simple setup would still change. Zero is a state of its
// own: offering a button that would do nothing, under a badge reading
// RECOMMENDED, is the exact "I cannot tell whether it is on" this screen was
// reported for.
$la_ob_todo = 0;
foreach ( $la_ob_items as $la_ob_item ) {
	if ( 'on' !== $la_ob_item['state'] ) {
		++$la_ob_todo;
	}
}

/**
 * The words attached to a state, before anything is applied.
 *
 * @param string $state on|partial|off.
 * @return array{0:string,1:string} [ chip text, chip variant ].
 */
$la_ob_chip = static function ( string $state ): array {
	if ( 'on' === $state ) {
		return array( __( 'Already on', 'login-armor' ), 'on' );
	}
	if ( 'partial' === $state ) {
		return array( __( 'Will be completed', 'login-armor' ), 'partial' );
	}
	return array( __( 'Will be turned on', 'login-armor' ), 'todo' );
};
?>
<div id="la-root" class="la-root la-onboarding-root">
	<style>
		/* The wizard reuses the same shell as every other admin tab: #la-root is
		   the full-bleed gray canvas (min-height:100vh, --la-bg-0) and .la-content
		   supplies the 32px left gutter that clears the WordPress admin menu plus
		   the 1400px column width. We do NOT override the root's width/margin here:
		   doing so previously turned the wizard into a cramped 900px island stuck
		   against the menu. These rules only style the onboarding-specific bits. */
		#la-root .la-onboarding{max-width:1100px;}
		#la-root .la-onboarding__head{margin:0 0 28px;max-width:680px;}
		#la-root .la-onboarding__head h1{font-size:26px;line-height:1.2;margin:0 0 8px;color:#0f172a;}
		#la-root .la-onboarding__head p{font-size:15px;line-height:1.5;color:#475569;}
		/* The two columns are deliberately NOT the same weight: the left one is
		   the only decision this screen carries, the right one is an inventory
		   of the decisions nobody can take for you. A symmetrical pair of
		   buttons read as two equal choices, and the second one only navigated. */
		#la-root .la-onboarding__cards{display:grid;grid-template-columns:1.35fr 1fr;gap:24px;align-items:start;}
		/* An explicit `display` beats the browser's own `[hidden]{display:none}`,
		   which is a one-line rule and loses to any id-qualified selector. The
		   report panel then rendered UNDER the two cards it replaces, with the
		   "Applying" button still on screen: the element answered hidden === true
		   while staying perfectly visible. Seen in a screenshot, not in a check. */
		#la-root .la-onboarding__cards[hidden],
		#la-root .la-onboarding__report[hidden]{display:none;}
		/* minmax(0,1fr), not 1fr: a bare 1fr cannot go under the widest line of
		   a card, and at 320px the two cards were 13px wider than the window. */
		@media(max-width:960px){#la-root .la-onboarding__cards{grid-template-columns:minmax(0,1fr);}}
		#la-root .la-onboarding__card{border:1px solid #e2e8f0;border-radius:14px;background:#fff;padding:28px;display:flex;flex-direction:column;box-shadow:0 1px 2px rgba(15,23,42,.04);}
		#la-root .la-onboarding__card--reco{border-color:#fcd34d;box-shadow:0 6px 18px -8px rgba(245,158,11,.4);}
		#la-root .la-onboarding__card--aside{background:#f8fafc;}
		#la-root .la-onboarding__card h2{font-size:18px;margin:0 0 8px;color:#0f172a;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
		#la-root .la-onboarding__card>p{color:#475569;font-size:13.5px;line-height:1.5;margin:0 0 14px;}
		#la-root .la-onboarding__note{font-size:12.5px;color:#64748b;line-height:1.45;margin:14px 0 16px;}
		#la-root .la-onboarding__btn{margin-top:auto;width:100%;display:inline-flex;align-items:center;justify-content:center;padding:11px 16px;border-radius:10px;font-size:14px;font-weight:600;border:1px solid transparent;cursor:pointer;text-decoration:none;transition:background .15s;}
		#la-root .la-onboarding__btn--primary{background:#f59e0b;color:#1e293b;}
		#la-root .la-onboarding__btn--primary:hover{background:#d97706;color:#1e293b;}
		#la-root .la-onboarding__btn--primary[disabled]{opacity:.6;cursor:default;}
		#la-root .la-onboarding__btn--neutral{background:#f1f5f9;color:#0f172a;border-color:#e2e8f0;}
		#la-root .la-onboarding__btn--neutral:hover{background:#e2e8f0;color:#0f172a;}
		#la-root .la-onboarding__rec{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.04em;color:#047857;background:#d1fae5;border-radius:999px;padding:2px 8px;}
		#la-root .la-onboarding__rec--done{color:#1d4ed8;background:#dbeafe;}
		/* One line per protection: what it is, where it lives, what state it is
		   in. The state is a word, never a colour alone: the colour repeats it. */
		#la-root .la-onboarding__list{list-style:none;margin:0 0 4px;padding:0;}
		#la-root .la-onboarding__row{display:flex;align-items:baseline;gap:10px;padding:9px 0;border-bottom:1px solid #f1f5f9;font-size:13.5px;line-height:1.45;}
		#la-root .la-onboarding__row:last-child{border-bottom:0;}
		#la-root .la-onboarding__row a{color:#0f172a;text-decoration:none;font-weight:600;border-bottom:1px solid #cbd5e1;}
		#la-root .la-onboarding__row a:hover{color:#b45309;border-bottom-color:#b45309;}
		#la-root .la-onboarding__detail{color:#64748b;font-size:12.5px;}
		#la-root .la-onboarding__chip{margin-left:auto;flex:none;font-size:11px;font-weight:700;letter-spacing:.02em;border-radius:999px;padding:3px 9px;white-space:nowrap;}
		#la-root .la-onboarding__chip--on{color:#047857;background:#d1fae5;}
		#la-root .la-onboarding__chip--now{color:#047857;background:#d1fae5;}
		#la-root .la-onboarding__chip--todo{color:#475569;background:#e2e8f0;}
		#la-root .la-onboarding__chip--partial{color:#92400e;background:#fef3c7;}
		#la-root .la-onboarding__chip--off{color:#334155;background:#e2e8f0;}
		#la-root .la-onboarding__chip--failed{color:#b91c1c;background:#fee2e2;}
		#la-root .la-onboarding__done{margin:6px 0 0;padding:12px 14px;border-radius:10px;background:#d1fae5;color:#065f46;font-size:13px;line-height:1.45;font-weight:600;}
		#la-root .la-onboarding__error{margin:0 0 14px;padding:12px 14px;border-radius:10px;background:#fee2e2;color:#991b1b;font-size:13px;line-height:1.45;}
		#la-root .la-onboarding__skip{margin-top:24px;}
		#la-root .la-onboarding__skip a{color:#475569;font-size:13px;}
		#la-root .la-onboarding__report{border:1px solid #a7f3d0;border-radius:14px;background:#fff;padding:28px;max-width:720px;box-shadow:0 6px 18px -8px rgba(5,150,105,.35);}
		#la-root .la-onboarding__report:focus{outline:2px solid #f59e0b;outline-offset:3px;}
		#la-root .la-onboarding__report h2{font-size:18px;margin:0 0 8px;color:#0f172a;}
		#la-root .la-onboarding__report>p{color:#475569;font-size:13.5px;line-height:1.5;margin:0 0 14px;}
		#la-root .la-onboarding__report .la-onboarding__btn{margin-top:18px;}
		@media(max-width:480px){#la-root .la-onboarding__card,#la-root .la-onboarding__report{padding:20px;}}
	</style>

	<main class="la-content la-onboarding">
	<div class="la-onboarding__head">
		<h1>
			<?php
			echo esc_html(
				$la_ob_first
					? __( 'Welcome to Login Armor', 'login-armor' )
					: __( 'Where this site stands', 'login-armor' )
			);
			?>
		</h1>
		<p>
			<?php
			echo esc_html(
				$la_ob_first
					? __( 'Choose how you want to start. You can change every setting afterwards, nothing here is permanent.', 'login-armor' )
					: __( 'Every line below is read from this site as it is right now. Nothing on this page changes anything until you ask for it.', 'login-armor' )
			);
			?>
		</p>
	</div>

	<div class="la-onboarding__cards" data-la-onboard-cards>
		<div class="la-onboarding__card la-onboarding__card--reco">
			<h2>
				<?php esc_html_e( 'Simple setup', 'login-armor' ); ?>
				<?php if ( $la_ob_todo > 0 ) : ?>
					<span class="la-onboarding__rec"><?php esc_html_e( 'RECOMMENDED', 'login-armor' ); ?></span>
				<?php else : ?>
					<span class="la-onboarding__rec la-onboarding__rec--done"><?php esc_html_e( 'ALREADY IN PLACE', 'login-armor' ); ?></span>
				<?php endif; ?>
			</h2>
			<p>
				<?php
				echo esc_html(
					$la_ob_todo > 0
						? __( 'The safe essentials: they protect your site with no risk of locking you out or breaking your theme. Here is what is already on, and what this would add.', 'login-armor' )
						: __( 'The safe essentials: they protect your site with no risk of locking you out or breaking your theme.', 'login-armor' )
				);
				?>
			</p>

			<?php if ( empty( $la_ob_items ) ) : ?>
				<p class="la-onboarding__error"><?php esc_html_e( 'The safe baseline could not be read on this install, so this screen cannot say what is on. Open the Settings tab: each module states its own state there.', 'login-armor' ); ?></p>
			<?php else : ?>
				<ul class="la-onboarding__list">
					<?php
					foreach ( $la_ob_items as $la_ob_item ) :
						list( $la_ob_text, $la_ob_variant ) = $la_ob_chip( (string) $la_ob_item['state'] );
						?>
						<li class="la-onboarding__row">
							<a href="<?php echo esc_url( $la_ob_settings . '#' . $la_ob_item['section'] ); ?>"><?php echo esc_html( (string) $la_ob_item['label'] ); ?></a>
							<?php if ( '' !== (string) $la_ob_item['detail'] ) : ?>
								<span class="la-onboarding__detail"><?php echo esc_html( (string) $la_ob_item['detail'] ); ?></span>
							<?php endif; ?>
							<span class="la-onboarding__chip la-onboarding__chip--<?php echo esc_attr( $la_ob_variant ); ?>"><?php echo esc_html( $la_ob_text ); ?></span>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>

			<p class="la-onboarding__note">
				<?php esc_html_e( 'The request firewall and the bot challenge start in monitor mode: they watch and record, they block nothing. After a week of monitoring, Login Armor tells you whether they can safely start blocking.', 'login-armor' ); ?>
			</p>

			<?php if ( $la_ob_todo > 0 ) : ?>
				<button type="button" class="la-onboarding__btn la-onboarding__btn--primary" data-la-onboard="simple">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: number of protections the simple setup would turn on. */
							_n( 'Turn on the %d missing protection', 'Turn on the %d missing protections', $la_ob_todo, 'login-armor' ),
							$la_ob_todo
						)
					);
					?>
				</button>
			<?php elseif ( ! empty( $la_ob_items ) ) : ?>
				<p class="la-onboarding__done"><?php esc_html_e( 'Everything the Simple setup turns on is already on. There is nothing to apply.', 'login-armor' ); ?></p>
			<?php endif; ?>
		</div>

		<div class="la-onboarding__card la-onboarding__card--aside">
			<h2><?php esc_html_e( 'What only you can decide', 'login-armor' ); ?></h2>
			<p><?php esc_html_e( 'The Simple setup never touches these five: each one can lock someone out or change what your visitors see, so none of them is switched on for you. Their state on this site:', 'login-armor' ); ?></p>
			<ul class="la-onboarding__list">
				<?php foreach ( $la_ob_manual as $la_ob_module ) : ?>
					<li class="la-onboarding__row">
						<a href="<?php echo esc_url( $la_ob_settings . '#' . $la_ob_module['section'] ); ?>"><?php echo esc_html( (string) $la_ob_module['label'] ); ?></a>
						<span class="la-onboarding__chip la-onboarding__chip--<?php echo 'on' === $la_ob_module['state'] ? 'on' : 'off'; ?>">
							<?php echo esc_html( 'on' === $la_ob_module['state'] ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ) ); ?>
						</span>
					</li>
				<?php endforeach; ?>
			</ul>
			<p class="la-onboarding__note"><?php esc_html_e( 'Each name above opens its own settings, where the module explains what it changes before you switch it on.', 'login-armor' ); ?></p>
		</div>
	</div>

	<div class="la-onboarding__report" data-la-onboard-report hidden tabindex="-1"></div>

	<p class="la-onboarding__skip">
		<a href="<?php echo esc_url( $la_ob_settings ); ?>"><?php esc_html_e( 'Go to the settings and configure it myself', 'login-armor' ); ?></a>
	</p>
	</main>
</div>

<script id="login-armor-onboarding">
(function () {
	var cfg = <?php echo wp_json_encode( array( 'ajaxUrl' => $ajax_url, 'nonce' => $admin_nonce, 'settings' => $la_ob_settings, 'l10n' => array( 'title' => __( 'Simple setup applied', 'login-armor' ), 'lead' => __( 'Here is the state of every protection now, read back from the site. Each name opens the setting it belongs to.', 'login-armor' ), 'now' => __( 'Turned on now', 'login-armor' ), 'already' => __( 'Already on', 'login-armor' ), 'partial' => __( 'Partly on', 'login-armor' ), 'failed' => __( 'Not enabled', 'login-armor' ), 'continue' => __( 'Continue to the settings', 'login-armor' ), 'working' => __( 'Applying…', 'login-armor' ), 'error' => __( 'Nothing was applied: the request failed. Your settings are unchanged.', 'login-armor' ) ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- wp_json_encode returns a safe JS literal. ?>;
	var cards = document.querySelector('[data-la-onboard-cards]');
	var panel = document.querySelector('[data-la-onboard-report]');

	function el(tag, cls, text) {
		var node = document.createElement(tag);
		if (cls) { node.className = cls; }
		// textContent throughout: every label and detail below is a translated
		// string coming back from the server, and a report about security that
		// injected markup would be its own defect.
		if (text !== undefined && text !== null) { node.textContent = text; }
		return node;
	}

	// One line of the report. `was` is the state before the writes, `state` the
	// state after: the pair is the only thing that can say "I turned this on"
	// rather than "this is on", which is the whole reason the server sends it.
	function chipFor(item) {
		if (item.state === 'partial') { return [cfg.l10n.partial, 'partial']; }
		if (item.state !== 'on') { return [cfg.l10n.failed, 'failed']; }
		return item.was === 'on' ? [cfg.l10n.already, 'on'] : [cfg.l10n.now, 'now'];
	}

	function renderReport(items) {
		panel.textContent = '';
		panel.appendChild(el('h2', null, cfg.l10n.title));
		panel.appendChild(el('p', null, cfg.l10n.lead));

		var list = el('ul', 'la-onboarding__list');
		items.forEach(function (item) {
			var row = el('li', 'la-onboarding__row');
			var link = el('a', null, item.label);
			link.href = cfg.settings + '#' + String(item.section || '');
			row.appendChild(link);
			if (item.detail) { row.appendChild(el('span', 'la-onboarding__detail', item.detail)); }
			var chip = chipFor(item);
			row.appendChild(el('span', 'la-onboarding__chip la-onboarding__chip--' + chip[1], chip[0]));
			list.appendChild(row);
		});
		panel.appendChild(list);

		var go = el('a', 'la-onboarding__btn la-onboarding__btn--primary', cfg.l10n.continue);
		go.href = cfg.settings;
		panel.appendChild(go);

		if (cards) { cards.hidden = true; }
		panel.hidden = false;
		panel.focus();
	}

	function fail(el0, label) {
		if (el0) { el0.removeAttribute('disabled'); el0.textContent = label; }
		panel.textContent = '';
		panel.appendChild(el('p', 'la-onboarding__error', cfg.l10n.error));
		panel.hidden = false;
		panel.focus();
	}

	function choose(mode, node) {
		var label = node ? node.textContent : '';
		if (node) { node.setAttribute('disabled', 'disabled'); node.textContent = cfg.l10n.working; }
		var body = 'action=login_armor_onboard&nonce=' + encodeURIComponent(cfg.nonce) + '&mode=' + encodeURIComponent(mode);
		fetch(cfg.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body
		}).then(function (r) { return r.json(); }).then(function (json) {
			var items = json && json.success && json.data && json.data.summary && json.data.summary.items;
			// No report means no proof. Saying "applied" on a response that
			// carries nothing to check is the failure this screen was reported
			// for, so an answer without items is treated as a failure.
			if (!items || !items.length) { fail(node, label); return; }
			renderReport(items);
		}).catch(function () {
			fail(node, label);
		});
	}

	document.querySelectorAll('[data-la-onboard]').forEach(function (node) {
		node.addEventListener('click', function (e) {
			e.preventDefault();
			choose(node.getAttribute('data-la-onboard'), node);
		});
	});
})();
</script>
<?php
// phpcs:ignore Generic.Files.OneObjectStructurePerFile -- view file, no class.
